import AppKit
import Darwin
import Foundation
import LocalAuthentication
import Security

struct ExpectedPresentationRow: Codable {
    let candidateIndex: Int
    let depth: Int
    let process: String
    let pid: String
    let executableOrCommand: String
}

struct ExpectedTree: Codable {
    let surfaceKind: String
    let inspectionState: String
    let requestKind: String
    let attribution: String
    let passwordInputVisible: Bool
    let candidateCount: Int
    let rows: [ExpectedPresentationRow]
}

struct LiveProcess {
    let pid: pid_t
    let parentPID: pid_t
    let name: String
    let executablePath: String
}

enum RequestMode: String {
    case localOwner = "local-owner"
    case localBiometrics = "local-biometrics"
    case localAccessControl = "local-access-control"
    case localRight = "local-right"
    case authorizationSessionOwner = "authorization-session-owner"
    case authorizationAdmin = "authorization-admin"
    case authorizationPassword = "authorization-password"
    case workspaceAdmin = "workspace-admin"
    case terminalPassword = "terminal-password"
    case terminalPAM = "terminal-pam"

    var usesTerminalPasswordRequest: Bool {
        self == .terminalPassword || self == .terminalPAM
    }

    var localAuthenticationPolicy: LAPolicy? {
        switch self {
        case .localOwner:
            .deviceOwnerAuthentication
        case .localBiometrics:
            .deviceOwnerAuthenticationWithBiometrics
        case .localAccessControl, .localRight,
             .authorizationSessionOwner, .authorizationAdmin,
             .authorizationPassword, .workspaceAdmin, .terminalPassword, .terminalPAM:
            nil
        }
    }

    var localizedReason: String? {
        switch self {
        case .localOwner:
            "Verify the Who Sudo'd live process tree with device-owner authentication."
        case .localBiometrics:
            "Verify the Who Sudo'd live process tree with Touch ID."
        case .localAccessControl:
            "Verify the Who Sudo'd live process tree with in-memory user presence."
        case .localRight:
            "Verify the Who Sudo'd live process tree with a transient right."
        case .authorizationSessionOwner, .authorizationAdmin,
             .authorizationPassword, .workspaceAdmin, .terminalPassword, .terminalPAM:
            nil
        }
    }

    var authorizationRight: String? {
        switch self {
        case .localOwner, .localBiometrics, .localAccessControl, .localRight,
             .workspaceAdmin, .terminalPassword, .terminalPAM:
            nil
        case .authorizationSessionOwner:
            "authenticate-session-owner"
        case .authorizationAdmin:
            "system.privilege.admin"
        case .authorizationPassword:
            "com.apple.installassistant.requestpassword"
        }
    }

    var expectedMetadata: (
        surfaceKind: String,
        requestKind: String,
        attribution: String
    ) {
        switch self {
        case .localOwner, .localBiometrics, .localAccessControl, .localRight:
            ("localAuthentication", "localAuthentication", "localAuthenticationLog")
        case .authorizationSessionOwner, .authorizationAdmin,
             .authorizationPassword, .workspaceAdmin:
            ("securityAgent", "authorization", "authorizationLog")
        case .terminalPassword:
            ("terminalPassword", "sudo", "heuristicSudo")
        case .terminalPAM:
            ("terminalPassword", "sudo", "pamConversation")
        }
    }
}

enum RequesterFailure: LocalizedError {
    case processUnavailable(pid_t)

    var errorDescription: String? {
        switch self {
        case let .processUnavailable(processID):
            "Could not inspect process \(processID)."
        }
    }
}

func fail(_ message: String, status: Int32) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(status)
}

func executablePath(processID: pid_t) -> String? {
    var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    let pathLength = pathBuffer.withUnsafeMutableBytes { bytes in
        proc_pidpath(processID, bytes.baseAddress, UInt32(bytes.count))
    }
    guard pathLength > 0 else {
        return nil
    }
    return String(
        decoding: pathBuffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
        as: UTF8.self
    )
}

func liveProcess(_ pid: pid_t) -> LiveProcess? {
    if pid == 1 {
        return LiveProcess(
            pid: 1,
            parentPID: 0,
            name: "launchd",
            executablePath: "/sbin/launchd"
        )
    }

    var information = proc_bsdinfo()
    let informationSize = Int32(MemoryLayout<proc_bsdinfo>.size)
    let bytesRead = withUnsafeMutablePointer(to: &information) { pointer in
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            pointer,
            informationSize
        )
    }
    guard bytesRead == informationSize else {
        return nil
    }

    guard let executablePath = executablePath(processID: pid) else {
        return nil
    }

    return LiveProcess(
        pid: pid,
        parentPID: pid_t(information.pbi_ppid),
        name: URL(fileURLWithPath: executablePath).lastPathComponent,
        executablePath: executablePath
    )
}

func enclosingApplicationPath(for executablePath: String) -> String? {
    var url = URL(fileURLWithPath: executablePath)
    while url.path != "/" {
        if url.pathExtension == "app",
           Bundle(url: url)?.executableURL?.resolvingSymlinksInPath().path
            == URL(fileURLWithPath: executablePath).resolvingSymlinksInPath().path {
            return url.path
        }
        url.deleteLastPathComponent()
    }
    return nil
}

func displayName(for process: LiveProcess) -> String {
    guard let appPath = enclosingApplicationPath(for: process.executablePath),
          let bundle = Bundle(url: URL(fileURLWithPath: appPath)) else {
        return process.name
    }
    return (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
        ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
        ?? process.name
}

func expectedTree(for requesterPID: pid_t, mode: RequestMode) throws -> ExpectedTree {
    var ancestry: [LiveProcess] = []
    var currentPID = requesterPID
    var visited: Set<pid_t> = []
    while currentPID > 0, visited.insert(currentPID).inserted {
        guard let process = liveProcess(currentPID) else {
            throw RequesterFailure.processUnavailable(currentPID)
        }
        ancestry.append(process)
        currentPID = process.parentPID
    }
    ancestry.reverse()
    var rows = ancestry.enumerated().map { depth, process in
        let name = displayName(for: process)
        return ExpectedPresentationRow(
            candidateIndex: 0,
            depth: depth,
            process: name,
            pid: String(process.pid),
            executableOrCommand: process.executablePath
        )
    }
    if mode.usesTerminalPasswordRequest {
        rows.append(
            ExpectedPresentationRow(
                candidateIndex: 0,
                depth: rows.count,
                process: "stat",
                pid: "—",
                executableOrCommand: "/usr/bin/stat -f %Su /var/root"
            )
        )
    }
    let metadata = mode.expectedMetadata
    return ExpectedTree(
        surfaceKind: metadata.surfaceKind,
        inspectionState: "complete",
        requestKind: metadata.requestKind,
        attribution: metadata.attribution,
        passwordInputVisible: mode == .terminalPAM,
        candidateCount: 1,
        rows: rows
    )
}

func writeExpectedTree(
    for requesterPID: pid_t,
    mode: RequestMode,
    to path: String
) throws {
    let expected = try expectedTree(for: requesterPID, mode: mode)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(expected).write(
        to: URL(fileURLWithPath: path),
        options: .atomic
    )
}

func writeExpectedTerminalPasswordTree(
    requesterPID: pid_t,
    sudoPID: pid_t,
    mode: RequestMode,
    to path: String
) throws {
    let base = try expectedTree(for: requesterPID, mode: mode)
    let sudoDepth = base.rows.count - 1
    var rows = Array(base.rows.dropLast())
    rows.append(
        ExpectedPresentationRow(
            candidateIndex: 0,
            depth: sudoDepth,
            process: "sudo",
            pid: String(sudoPID),
            executableOrCommand: "/usr/bin/sudo"
        )
    )
    rows.append(
        ExpectedPresentationRow(
            candidateIndex: 0,
            depth: sudoDepth + 1,
            process: "stat",
            pid: "—",
            executableOrCommand: "/usr/bin/stat -f %Su /var/root"
        )
    )
    let expected = ExpectedTree(
        surfaceKind: base.surfaceKind,
        inspectionState: base.inspectionState,
        requestKind: base.requestKind,
        attribution: base.attribution,
        passwordInputVisible: base.passwordInputVisible,
        candidateCount: base.candidateCount,
        rows: rows
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(expected).write(
        to: URL(fileURLWithPath: path),
        options: .atomic
    )
}

func stopTerminalChild(_ processID: pid_t, masterDescriptor: Int32) {
    close(masterDescriptor)
    if kill(processID, 0) == 0 {
        kill(processID, SIGTERM)
    }
    var status: Int32 = 0
    _ = waitpid(processID, &status, 0)
}

func waitForSudoExecutable(
    processID: pid_t,
    timeout: TimeInterval
) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if executablePath(processID: processID) == "/usr/bin/sudo" {
            return true
        }
        Thread.sleep(forTimeInterval: 0.01)
    }
    return false
}

func processWasStopped(_ status: Int32) -> Bool {
    let waitStatusMask: Int32 = 0x7f
    let stoppedStatus: Int32 = 0x7f
    let continuedSignal: Int32 = SIGCONT
    let signal = (status >> 8) & 0xff
    return status & waitStatusMask == stoppedStatus
        && signal != continuedSignal
}

@MainActor
func presentLiveCheckWindow(
    _ window: NSWindow,
    application: NSApplication
) {
    application.activate(ignoringOtherApps: true)
    window.makeKeyAndOrderFront(nil)
    window.orderFrontRegardless()
}

@MainActor
final class TerminalPasswordRequestSupervisor: NSObject {
    private let application: NSApplication
    private let window: NSWindow
    private let childProcessID: pid_t
    private let masterDescriptor: Int32
    private let deadline: Date
    private var timer: Timer?

    init(
        application: NSApplication,
        window: NSWindow,
        childProcessID: pid_t,
        masterDescriptor: Int32,
        timeout: TimeInterval
    ) {
        self.application = application
        self.window = window
        self.childProcessID = childProcessID
        self.masterDescriptor = masterDescriptor
        self.deadline = Date().addingTimeInterval(timeout)
    }

    func run() -> Never {
        presentLiveCheckWindow(window, application: application)
        timer = Timer.scheduledTimer(
            timeInterval: 0.02,
            target: self,
            selector: #selector(poll),
            userInfo: nil,
            repeats: true
        )
        application.run()
        fail("The terminal-password live check stopped unexpectedly.", status: 70)
    }

    @objc private func poll() {
        var status: Int32 = 0
        let result = waitpid(childProcessID, &status, WNOHANG)
        if result == childProcessID {
            close(masterDescriptor)
            fail("The password-only sudo request exited early.", status: 2)
        }
        if Date() >= deadline {
            stopTerminalChild(childProcessID, masterDescriptor: masterDescriptor)
            fail("The password-only sudo request timed out.", status: 124)
        }
        if !application.isActive {
            presentLiveCheckWindow(window, application: application)
        }
    }
}

@MainActor
func runTerminalPasswordRequest(
    mode: RequestMode,
    expectedPath: String,
    timeout: TimeInterval
) -> Never {
    let application = NSApplication.shared
    application.setActivationPolicy(.regular)
    application.finishLaunching()

    let window = NSWindow(
        contentRect: CGRect(x: 0, y: 0, width: 520, height: 220),
        styleMask: [.titled, .closable],
        backing: .buffered,
        defer: false
    )
    window.title = "Who Sudo'd terminal password live check"
    window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
    let label = NSTextField(labelWithString: "A password-only sudo request is active in a private terminal.")
    label.font = .systemFont(ofSize: 16, weight: .medium)
    label.alignment = .center
    label.frame = CGRect(x: 32, y: 84, width: 456, height: 52)
    window.contentView?.addSubview(label)
    window.center()
    presentLiveCheckWindow(window, application: application)

    var masterDescriptor: Int32 = -1
    var childProcessID: pid_t = 0
    childProcessID = forkpty(&masterDescriptor, nil, nil, nil)
    guard childProcessID >= 0 else {
        fail("Could not create the private terminal: \(String(cString: strerror(errno)))", status: 71)
    }

    if childProcessID == 0 {
        raise(SIGSTOP)
        let values = [
            "/usr/bin/sudo",
            "-k",
            "--",
            "/usr/bin/stat",
            "-f",
            "%Su",
            "/var/root"
        ]
        var pointers = values.map { strdup($0) }
        pointers.append(nil)
        execv("/usr/bin/sudo", &pointers)
        _exit(127)
    }

    var stoppedStatus: Int32 = 0
    guard waitpid(childProcessID, &stoppedStatus, WUNTRACED) == childProcessID,
          processWasStopped(stoppedStatus) else {
        stopTerminalChild(childProcessID, masterDescriptor: masterDescriptor)
        fail("The private terminal did not enter its warm-up state.", status: 70)
    }
    let warmUpDeadline = Date().addingTimeInterval(0.75)
    while Date() < warmUpDeadline {
        RunLoop.main.run(until: Date().addingTimeInterval(0.02))
    }
    guard kill(childProcessID, SIGCONT) == 0 else {
        stopTerminalChild(childProcessID, masterDescriptor: masterDescriptor)
        fail("Could not continue the private terminal.", status: 70)
    }

    guard waitForSudoExecutable(
        processID: childProcessID,
        timeout: 2
    ) else {
        stopTerminalChild(childProcessID, masterDescriptor: masterDescriptor)
        fail("The private terminal did not start sudo.", status: 70)
    }

    do {
        try writeExpectedTerminalPasswordTree(
            requesterPID: getpid(),
            sudoPID: childProcessID,
            mode: mode,
            to: expectedPath
        )
    } catch {
        stopTerminalChild(childProcessID, masterDescriptor: masterDescriptor)
        fail("Could not write the expected process tree: \(error.localizedDescription)", status: 74)
    }

    print("mode=\(mode.rawValue) requesterPID=\(getpid()) sudoPID=\(childProcessID)")
    fflush(stdout)
    TerminalPasswordRequestSupervisor(
        application: application,
        window: window,
        childProcessID: childProcessID,
        masterDescriptor: masterDescriptor,
        timeout: timeout
    ).run()
}

func requestAuthorizationRight(
    _ rightName: String,
    username: String? = nil,
    password: String? = nil
) -> OSStatus {
    var authorization: AuthorizationRef?
    let createStatus = AuthorizationCreate(
        nil,
        nil,
        [],
        &authorization
    )
    guard createStatus == errAuthorizationSuccess,
          let authorization else {
        return createStatus
    }
    defer {
        AuthorizationFree(authorization, [.destroyRights])
    }

    return rightName.withCString { name in
        var item = AuthorizationItem(
            name: name,
            valueLength: 0,
            value: nil,
            flags: 0
        )
        return withUnsafeMutablePointer(to: &item) { itemPointer in
            var rights = AuthorizationRights(count: 1, items: itemPointer)
            if let username, let password {
                return kAuthorizationEnvironmentUsername.withCString { environmentNamePointer in
                    kAuthorizationEnvironmentPassword.withCString { passwordNamePointer in
                        username.withCString { usernamePointer in
                            password.withCString { passwordPointer in
                                var environmentItems = [
                                    AuthorizationItem(
                                        name: environmentNamePointer,
                                        valueLength: strlen(usernamePointer),
                                        value: UnsafeMutableRawPointer(mutating: usernamePointer),
                                        flags: 0
                                    ),
                                    AuthorizationItem(
                                        name: passwordNamePointer,
                                        valueLength: strlen(passwordPointer),
                                        value: UnsafeMutableRawPointer(mutating: passwordPointer),
                                        flags: 0
                                    ),
                                ]
                                return environmentItems.withUnsafeMutableBufferPointer { environmentItemsPointer in
                                    var environment = AuthorizationEnvironment(
                                        count: 2,
                                        items: environmentItemsPointer.baseAddress
                                    )
                                    return AuthorizationCopyRights(
                                        authorization,
                                        &rights,
                                        &environment,
                                        [.interactionAllowed, .extendRights],
                                        nil
                                    )
                                }
                            }
                        }
                    }
                }
            }
            return AuthorizationCopyRights(
                authorization,
                &rights,
                nil,
                [.interactionAllowed, .extendRights],
                nil
            )
        }
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 3,
      let mode = RequestMode(rawValue: arguments[0]),
      arguments[1].hasPrefix("/"),
      let timeout = TimeInterval(arguments[2]),
      timeout > 0 else {
    fail(
        "Usage: WhoSudodLiveRequester <local-owner|local-biometrics|local-access-control|local-right|authorization-session-owner|authorization-admin|authorization-password|workspace-admin|terminal-password|terminal-pam> EXPECTED_JSON TIMEOUT_SECONDS",
        status: 64
    )
}

let context: LAContext?
if let policy = mode.localAuthenticationPolicy {
    let localContext = LAContext()
    localContext.localizedCancelTitle = "Cancel"
    var availabilityError: NSError?
    guard localContext.canEvaluatePolicy(policy, error: &availabilityError) else {
        fail(
            "Local Authentication is unavailable: \(availabilityError?.localizedDescription ?? "unknown error")",
            status: 77
        )
    }
    context = localContext
} else {
    context = nil
}

if !mode.usesTerminalPasswordRequest {
    do {
        try writeExpectedTree(
            for: getpid(),
            mode: mode,
            to: arguments[1]
        )
    } catch {
        fail("Could not write the expected process tree: \(error.localizedDescription)", status: 74)
    }
}

print("mode=\(mode.rawValue) requesterPID=\(getpid())")
fflush(stdout)

if mode.usesTerminalPasswordRequest {
    runTerminalPasswordRequest(
        mode: mode,
        expectedPath: arguments[1],
        timeout: timeout
    )
}

if let policy = mode.localAuthenticationPolicy,
   let localizedReason = mode.localizedReason,
   let context {
    context.evaluatePolicy(
        policy,
        localizedReason: localizedReason
    ) { success, error in
        let description = error?.localizedDescription ?? "none"
        print("success=\(success) error=\(description)")
        fflush(stdout)
        exit(success ? 0 : 2)
    }

    RunLoop.main.run(until: Date().addingTimeInterval(timeout))
    context.invalidate()
    fail("The Local Authentication request timed out.", status: 124)
}

if mode == .localAccessControl,
   let localizedReason = mode.localizedReason {
    var creationError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .userPresence,
        &creationError
    ) else {
        let description = creationError?.takeRetainedValue().localizedDescription
            ?? "unknown error"
        fail("Could not create in-memory access control: \(description)", status: 77)
    }

    let accessControlContext = LAContext()
    accessControlContext.localizedCancelTitle = "Cancel"
    accessControlContext.evaluateAccessControl(
        accessControl,
        operation: .useItem,
        localizedReason: localizedReason
    ) { success, error in
        let description = error?.localizedDescription ?? "none"
        print("success=\(success) error=\(description)")
        fflush(stdout)
        exit(success ? 0 : 2)
    }

    RunLoop.main.run(until: Date().addingTimeInterval(timeout))
    accessControlContext.invalidate()
    fail("The access-control request timed out.", status: 124)
}

if mode == .localRight,
   let localizedReason = mode.localizedReason {
    let right = LARight(requirement: .default)
    right.authorize(localizedReason: localizedReason) { error in
        let description = error?.localizedDescription ?? "none"
        print("success=\(error == nil) error=\(description)")
        fflush(stdout)
        exit(error == nil ? 0 : 2)
    }

    RunLoop.main.run(until: Date().addingTimeInterval(timeout))
    fail("The transient-right request timed out.", status: 124)
}

if let authorizationRight = mode.authorizationRight {
    let username = mode == .authorizationPassword
        ? "who-sudod-test-user"
        : nil
    let status = requestAuthorizationRight(
        authorizationRight,
        username: username,
        password: username == nil ? nil : "not-a-real-password"
    )
    print("authorizationStatus=\(status)")
    fflush(stdout)
    exit(status == errAuthorizationSuccess ? 0 : 2)
}

if mode == .workspaceAdmin {
    NSWorkspace.shared.requestAuthorization(to: .setAttributes) { authorization, error in
        let success = authorization != nil && error == nil
        let description = error?.localizedDescription ?? "none"
        print("success=\(success) error=\(description)")
        fflush(stdout)
        exit(success ? 0 : 2)
    }

    RunLoop.main.run(until: Date().addingTimeInterval(timeout))
    fail("The workspace authorization request timed out.", status: 124)
}

fail("The requester mode is not implemented.", status: 70)

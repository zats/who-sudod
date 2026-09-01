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

    var localAuthenticationPolicy: LAPolicy? {
        switch self {
        case .localOwner:
            .deviceOwnerAuthentication
        case .localBiometrics:
            .deviceOwnerAuthenticationWithBiometrics
        case .localAccessControl, .localRight,
             .authorizationSessionOwner, .authorizationAdmin,
             .authorizationPassword, .workspaceAdmin:
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
             .authorizationPassword, .workspaceAdmin:
            nil
        }
    }

    var authorizationRight: String? {
        switch self {
        case .localOwner, .localBiometrics, .localAccessControl, .localRight,
             .workspaceAdmin:
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

    var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    let pathLength = pathBuffer.withUnsafeMutableBytes { bytes in
        proc_pidpath(pid, bytes.baseAddress, UInt32(bytes.count))
    }
    guard pathLength > 0 else {
        return nil
    }

    let executablePath = String(
        decoding: pathBuffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
        as: UTF8.self
    )

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
    let rows = ancestry.enumerated().map { depth, process in
        let name = displayName(for: process)
        return ExpectedPresentationRow(
            candidateIndex: 0,
            depth: depth,
            process: name,
            pid: String(process.pid),
            executableOrCommand: process.executablePath
        )
    }
    let metadata = mode.expectedMetadata
    return ExpectedTree(
        surfaceKind: metadata.surfaceKind,
        inspectionState: "complete",
        requestKind: metadata.requestKind,
        attribution: metadata.attribution,
        candidateCount: 1,
        rows: rows
    )
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
        "Usage: WhoSudodLiveRequester <local-owner|local-biometrics|local-access-control|local-right|authorization-session-owner|authorization-admin|authorization-password|workspace-admin> EXPECTED_JSON TIMEOUT_SECONDS",
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

do {
    let expected = try expectedTree(for: getpid(), mode: mode)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(expected).write(
        to: URL(fileURLWithPath: arguments[1]),
        options: .atomic
    )
} catch {
    fail("Could not write the expected process tree: \(error.localizedDescription)", status: 74)
}

print("mode=\(mode.rawValue) requesterPID=\(getpid())")
fflush(stdout)

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

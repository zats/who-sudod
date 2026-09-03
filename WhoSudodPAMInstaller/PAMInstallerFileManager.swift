import CryptoKit
import Darwin
import Foundation
import MachO
import Security

enum PAMInstallerFileError: LocalizedError {
    case helperIsNotRoot
    case unsupportedArchitecture
    case unsafeFile(String)
    case missingPayload
    case invalidPayloadSignature(OSStatus)
    case invalidApplicationSignature(OSStatus)
    case invalidHelperSignature(OSStatus)
    case runningHelperMismatch
    case concurrentModification(String)
    case posix(operation: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .helperIsNotRoot:
            "The PAM helper is not running as root."
        case .unsupportedArchitecture:
            "This PAM helper supports Apple silicon only."
        case .unsafeFile(let path):
            "The PAM helper refused an unsafe file at \(path)."
        case .missingPayload:
            "A bundled PAM component is missing."
        case .invalidPayloadSignature(let status):
            "A bundled PAM component failed code-signature validation (\(status))."
        case .invalidApplicationSignature(let status):
            "The Who Sudo'd application failed code-signature validation (\(status))."
        case .invalidHelperSignature(let status):
            "The PAM helper failed code-signature validation (\(status))."
        case .runningHelperMismatch:
            "The running PAM helper does not match the signed application on disk."
        case .concurrentModification(let path):
            "The PAM helper stopped because \(path) changed during the operation. Try again."
        case .posix(let operation, let code):
            "\(operation) failed: \(String(cString: strerror(code)))."
        }
    }
}

struct PAMInstallerMutationResult {
    let inspection: PAMIntegrationInspection
    let operationError: String?
}

final class PAMInstallerFileManager {
    private struct FileVersion: Equatable {
        let device: dev_t
        let inode: ino_t
        let userID: uid_t
        let groupID: gid_t
        let mode: mode_t
        let linkCount: nlink_t
        let flags: UInt32
        let size: off_t
        let modificationSeconds: Int64
        let modificationNanoseconds: Int64
        let changeSeconds: Int64
        let changeNanoseconds: Int64

        init(_ metadata: stat) {
            device = metadata.st_dev
            inode = metadata.st_ino
            userID = metadata.st_uid
            groupID = metadata.st_gid
            mode = metadata.st_mode
            linkCount = metadata.st_nlink
            flags = metadata.st_flags
            size = metadata.st_size
            modificationSeconds = Int64(metadata.st_mtimespec.tv_sec)
            modificationNanoseconds = Int64(metadata.st_mtimespec.tv_nsec)
            changeSeconds = Int64(metadata.st_ctimespec.tv_sec)
            changeNanoseconds = Int64(metadata.st_ctimespec.tv_nsec)
        }
    }

    private struct FileSnapshot {
        let data: Data
        let metadata: stat
        let version: FileVersion
    }

    private struct PayloadActivation {
        let previousDirectoryPath: String?
    }

    private final class OpenPayload {
        let path: String
        let descriptor: Int32
        let version: FileVersion

        init(path: String, descriptor: Int32, version: FileVersion) {
            self.path = path
            self.descriptor = descriptor
            self.version = version
        }

        deinit {
            close(descriptor)
        }
    }

    private struct InstallTransactionOperations: PAMInstallTransactionOperations {
        unowned let files: PAMInstallerFileManager
        let module: OpenPayload
        let terminalReader: OpenPayload
        let applicationURL: URL
        let initialConfiguration: FileSnapshot
        let activatedConfiguration: Data
        let configurationInitiallyReferencesPayloads: Bool

        func activateCompletePayloadSet() throws -> PayloadActivation {
            try files.replacePayloadSetAtomically(
                module: module,
                terminalReader: terminalReader
            )
        }

        func validateActivatedPayloadSet() throws {
            try files.requireManagedPayloadDirectory(
                at: files.installationDirectoryPath,
                requiresBothPayloads: true
            )
            try files.validateApplicationBundleForInstall(expectedURL: applicationURL)
            try files.requireUnchangedPayload(module)
            try files.requireUnchangedPayload(terminalReader)
        }

        func persistActivatedPayloadSet() throws {
            try files.persistenceBarrier(
                path: (files.installationDirectoryPath as NSString).deletingLastPathComponent
            )
        }

        func validateConfigurationBeforeCommit() throws {
            try files.managedConfigurationGuard.requireLocalConfiguration()
        }

        func commitConfigurationReferencingPayloads() throws {
            guard activatedConfiguration != initialConfiguration.data else {
                return
            }
            try files.atomicReplaceConfiguration(
                with: activatedConfiguration,
                replacing: initialConfiguration
            )
        }

        func discardPreviousPayloadSet(after activation: PayloadActivation) {
            files.commitPayloadActivation(activation)
        }

        func recoverFromPrecommitFailure(
            after activation: PayloadActivation,
            activationWasPersisted: Bool
        ) {
            if configurationInitiallyReferencesPayloads {
                // The old configuration already calls this fixed payload path.
                // Keep the newly published complete set instead of restoring a
                // previous set that may be the reason repair was required.
                // Before the activation barrier succeeds, also retain the old
                // directory because a restart can restore its name mapping.
                if activationWasPersisted {
                    files.commitPayloadActivation(activation)
                }
            } else {
                try? files.rollbackPayloadActivation(activation)
            }
        }
    }

    private struct UninstallTransactionOperations: PAMUninstallTransactionOperations {
        unowned let files: PAMInstallerFileManager
        let initialConfiguration: FileSnapshot
        let updatedConfiguration: Data

        func commitConfigurationWithoutPayloadReferences() throws {
            guard updatedConfiguration != initialConfiguration.data else {
                return
            }
            try files.atomicReplaceConfiguration(
                with: updatedConfiguration,
                replacing: initialConfiguration
            )
        }

        func persistConfigurationWithoutPayloadReferences() throws {
            try files.persistenceBarrier(
                path: (files.configurationPath as NSString).deletingLastPathComponent
            )
        }

        func validatePayloadRemoval() throws {
            try files.managedConfigurationGuard.requireLocalConfiguration()
            let currentConfiguration = try files.secureFileSnapshot(
                path: files.configurationPath
            )
            guard currentConfiguration.data == updatedConfiguration,
                  !PAMConfigurationEditor.hasOwnedPayloadReference(
                    in: currentConfiguration.data
                  ) else {
                throw PAMInstallerFileError.concurrentModification(
                    files.configurationPath
                )
            }
        }

        func removePayloadSet() throws {
            try files.removeInstalledPayloads()
        }
    }

    private let configurationPath = PAMIntegrationConstants.sudoConfigurationPath
    private let installationDirectoryPath = PAMIntegrationConstants.installationDirectoryPath
    private let installedModulePath = PAMIntegrationConstants.installedModulePath
    private let installedTerminalReaderPath = PAMIntegrationConstants.installedTerminalReaderPath
    private let operationLockDirectoryPath = "/Library/Security"
    private let managedConfigurationGuard: PAMManagedConfigurationGuard

    init(managedConfigurationGuard: PAMManagedConfigurationGuard = .system) {
        self.managedConfigurationGuard = managedConfigurationGuard
    }

    func inspect() -> PAMIntegrationInspection {
        do {
            try validateRuntime()
            let modulePayloadURL = try embeddedPayloadURL(
                relativePath: PAMIntegrationConstants.embeddedModuleRelativePath
            )
            let terminalReaderPayloadURL = try embeddedPayloadURL(
                relativePath: PAMIntegrationConstants.embeddedTerminalReaderRelativePath
            )
            try validatePayloadSignature(
                at: modulePayloadURL,
                requirement: PAMIntegrationConstants.moduleSigningRequirement
            )
            try validatePayloadSignature(
                at: terminalReaderPayloadURL,
                requirement: PAMIntegrationConstants.terminalReaderSigningRequirement
            )
            let configuration = try secureFileSnapshot(path: configurationPath).data
            let installedModule = try optionalSecureRead(path: installedModulePath)
            let installedTerminalReader = try optionalSecureRead(path: installedTerminalReaderPath)
            let modulePayload = try secureRead(path: modulePayloadURL.path)
            let terminalReaderPayload = try secureRead(path: terminalReaderPayloadURL.path)
            let installationDirectoryMatchesRuntime = try hasExpectedInstallationDirectoryMetadata()
            let installedModuleMetadataIsValid = try installedModule.map {
                _ = $0
                return try hasExpectedInstalledPayloadMetadata(at: installedModulePath)
            } ?? false
            let installedTerminalReaderMetadataIsValid = try installedTerminalReader.map {
                _ = $0
                return try hasExpectedInstalledPayloadMetadata(at: installedTerminalReaderPath)
            } ?? false
            return PAMConfigurationEditor.inspect(
                configuration: configuration,
                moduleExists: installedModule != nil,
                moduleMatchesPayload: installationDirectoryMatchesRuntime
                    && installedModuleMetadataIsValid
                    && installedModule.map(SHA256.hash(data:)) == SHA256.hash(data: modulePayload),
                terminalReaderExists: installedTerminalReader != nil,
                terminalReaderMatchesPayload: installationDirectoryMatchesRuntime
                    && installedTerminalReaderMetadataIsValid
                    && installedTerminalReader.map(SHA256.hash(data:))
                        == SHA256.hash(data: terminalReaderPayload)
            )
        } catch {
            return PAMIntegrationInspection(
                state: .unsupported,
                detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
        }
    }

    func install(expectedBuildIdentity: Data) -> PAMInstallerMutationResult {
        do {
            try validateRuntime()
            let inspection = try withExclusiveOperationLock {
                try managedConfigurationGuard.requireLocalConfiguration()
                let modulePayloadURL = try embeddedPayloadURL(
                    relativePath: PAMIntegrationConstants.embeddedModuleRelativePath
                )
                let terminalReaderPayloadURL = try embeddedPayloadURL(
                    relativePath: PAMIntegrationConstants.embeddedTerminalReaderRelativePath
                )
                let modulePayload = try openPayload(at: modulePayloadURL.path)
                let terminalReaderPayload = try openPayload(at: terminalReaderPayloadURL.path)
                try requireExpectedBuildIdentity(expectedBuildIdentity)
                let applicationURL = try validateApplicationBundleForInstall()
                try requireUnchangedPayload(modulePayload)
                try requireUnchangedPayload(terminalReaderPayload)
                try validatePayloadSignature(
                    at: modulePayloadURL,
                    requirement: PAMIntegrationConstants.moduleSigningRequirement
                )
                try validatePayloadSignature(
                    at: terminalReaderPayloadURL,
                    requirement: PAMIntegrationConstants.terminalReaderSigningRequirement
                )

                let initialConfiguration = try secureFileSnapshot(path: configurationPath)
                let activatedConfiguration = try PAMConfigurationEditor.installing(
                    in: initialConfiguration.data
                )
                try PAMInstallTransactionCoordinator(
                    operations: InstallTransactionOperations(
                        files: self,
                        module: modulePayload,
                        terminalReader: terminalReaderPayload,
                        applicationURL: applicationURL,
                        initialConfiguration: initialConfiguration,
                        activatedConfiguration: activatedConfiguration,
                        configurationInitiallyReferencesPayloads:
                            PAMConfigurationEditor.hasOwnedPayloadReference(
                                in: initialConfiguration.data
                            )
                    )
                ).run()
                return inspect()
            }
            return PAMInstallerMutationResult(
                inspection: inspection,
                operationError: inspection.state == .installed
                    ? nil
                    : inspection.detail ?? "The PAM installation could not be verified."
            )
        } catch {
            return PAMInstallerMutationResult(
                inspection: inspect(),
                operationError: (error as? LocalizedError)?.errorDescription
                    ?? error.localizedDescription
            )
        }
    }

    func uninstall(expectedBuildIdentity: Data) -> PAMInstallerMutationResult {
        do {
            try validateRuntime()
            let inspection = try withExclusiveOperationLock {
                try managedConfigurationGuard.requireLocalConfiguration()
                try requireExpectedBuildIdentity(expectedBuildIdentity)
                let configuration = try secureFileSnapshot(path: configurationPath)
                let updatedConfiguration = try PAMConfigurationEditor.uninstalling(
                    from: configuration.data
                )
                try managedConfigurationGuard.requireLocalConfiguration()
                try PAMUninstallTransactionCoordinator(
                    operations: UninstallTransactionOperations(
                        files: self,
                        initialConfiguration: configuration,
                        updatedConfiguration: updatedConfiguration
                    )
                ).run()
                return PAMIntegrationInspection(state: .notInstalled, detail: nil)
            }
            return PAMInstallerMutationResult(
                inspection: inspection,
                operationError: inspection.state == .notInstalled
                    ? nil
                    : inspection.detail ?? "The PAM removal could not be verified."
            )
        } catch {
            return PAMInstallerMutationResult(
                inspection: inspect(),
                operationError: (error as? LocalizedError)?.errorDescription
                    ?? error.localizedDescription
            )
        }
    }

    private func requireExpectedBuildIdentity(_ expectedBuildIdentity: Data) throws {
        guard try PAMHelperBuildIdentity.currentHelper().matches(
            token: expectedBuildIdentity
        ) else {
            throw PAMHelperBuildIdentityError.mismatch
        }
    }

    private func validateRuntime() throws {
        guard geteuid() == 0 else {
            throw PAMInstallerFileError.helperIsNotRoot
        }
        #if !arch(arm64)
        throw PAMInstallerFileError.unsupportedArchitecture
        #endif
        try managedConfigurationGuard.requireLocalConfiguration()
        try validateRunningHelperSignature()
        try requireSafeDirectory(path: "/etc/pam.d", exactMode: 0o755)
        try requireSafeDirectory(path: "/Library", exactMode: 0o755)
        try requireSafeDirectory(path: "/Library/Security", exactMode: 0o755)
    }

    private func withExclusiveOperationLock<Result>(
        _ operation: () throws -> Result
    ) throws -> Result {
        let descriptor = open(
            operationLockDirectoryPath,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
        )
        guard descriptor >= 0 else {
            throw posixError("Open the PAM operation lock")
        }
        defer { close(descriptor) }

        var descriptorMetadata = stat()
        guard fstat(descriptor, &descriptorMetadata) == 0 else {
            throw posixError("Inspect the PAM operation lock")
        }
        guard descriptorMetadata.st_mode & S_IFMT == S_IFDIR,
              descriptorMetadata.st_uid == 0,
              descriptorMetadata.st_gid == 0,
              descriptorMetadata.st_mode & mode_t(0o7777) == mode_t(0o755) else {
            throw PAMInstallerFileError.unsafeFile(operationLockDirectoryPath)
        }
        try requireNoExtendedACL(fd: descriptor, path: operationLockDirectoryPath)

        while flock(descriptor, LOCK_EX) != 0 {
            guard errno == EINTR else {
                throw posixError("Lock the PAM operation")
            }
        }
        defer { _ = flock(descriptor, LOCK_UN) }

        var pathMetadata = stat()
        guard lstat(operationLockDirectoryPath, &pathMetadata) == 0,
              pathMetadata.st_mode & S_IFMT == S_IFDIR,
              pathMetadata.st_dev == descriptorMetadata.st_dev,
              pathMetadata.st_ino == descriptorMetadata.st_ino else {
            throw PAMInstallerFileError.unsafeFile(operationLockDirectoryPath)
        }
        return try operation()
    }

    private func embeddedPayloadURL(relativePath: String) throws -> URL {
        let payloadURL = try applicationBundleURL().appendingPathComponent(relativePath)
        guard FileManager.default.fileExists(atPath: payloadURL.path) else {
            throw PAMInstallerFileError.missingPayload
        }
        return payloadURL
    }

    private func validateRunningHelperSignature() throws {
        var runningCode: SecCode?
        var status = SecCodeCopySelf([], &runningCode)
        guard status == errSecSuccess, let runningCode else {
            throw PAMInstallerFileError.invalidHelperSignature(status)
        }
        var runningStaticCode: SecStaticCode?
        status = SecCodeCopyStaticCode(runningCode, [], &runningStaticCode)
        guard status == errSecSuccess, let runningStaticCode else {
            throw PAMInstallerFileError.invalidHelperSignature(status)
        }

        var helperRequirement: SecRequirement?
        status = SecRequirementCreateWithString(
            PAMIntegrationConstants.helperSigningRequirement as CFString,
            [],
            &helperRequirement
        )
        guard status == errSecSuccess, let helperRequirement else {
            throw PAMInstallerFileError.invalidHelperSignature(status)
        }

        status = SecStaticCodeCheckValidity(
            runningStaticCode,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            helperRequirement
        )
        guard status == errSecSuccess else {
            throw PAMInstallerFileError.invalidHelperSignature(status)
        }
    }

    @discardableResult
    private func validateApplicationBundleForInstall(expectedURL: URL? = nil) throws -> URL {
        let applicationURL = try applicationBundleURL()
        if let expectedURL,
           applicationURL.standardizedFileURL != expectedURL.standardizedFileURL {
            throw PAMInstallerFileError.runningHelperMismatch
        }

        var applicationCode: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(applicationURL as CFURL, [], &applicationCode)
        guard status == errSecSuccess, let applicationCode else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }

        var applicationRequirement: SecRequirement?
        status = SecRequirementCreateWithString(
            PAMIntegrationConstants.applicationSigningRequirement as CFString,
            [],
            &applicationRequirement
        )
        guard status == errSecSuccess, let applicationRequirement else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }

        let validationFlags = SecCSFlags(
            rawValue: kSecCSStrictValidate
                | kSecCSCheckNestedCode
                | kSecCSCheckAllArchitectures
                | kSecCSRestrictSymlinks
        )
        status = SecStaticCodeCheckValidity(
            applicationCode,
            validationFlags,
            applicationRequirement
        )
        guard status == errSecSuccess else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }

        var runningCode: SecCode?
        status = SecCodeCopySelf([], &runningCode)
        guard status == errSecSuccess, let runningCode else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }
        var runningStaticCode: SecStaticCode?
        status = SecCodeCopyStaticCode(runningCode, [], &runningStaticCode)
        guard status == errSecSuccess, let runningStaticCode else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }
        let helperURL = applicationURL.appendingPathComponent(
            "Contents/Library/LaunchServices/WhoSudodPAMInstaller"
        )
        var helperCode: SecStaticCode?
        status = SecStaticCodeCreateWithPath(helperURL as CFURL, [], &helperCode)
        guard status == errSecSuccess, let helperCode else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }
        guard try codeDirectoryHash(for: runningStaticCode)
            == codeDirectoryHash(for: helperCode) else {
            throw PAMInstallerFileError.runningHelperMismatch
        }
        return applicationURL
    }

    private func codeDirectoryHash(for code: SecStaticCode) throws -> Data {
        var information: CFDictionary?
        let status = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        guard status == errSecSuccess,
              let dictionary = information as? [String: Any],
              let hash = dictionary[kSecCodeInfoUnique as String] as? Data else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }
        return hash
    }

    private func applicationBundleURL() throws -> URL {
        let executableURL = try currentExecutableURL()
        let applicationURL = executableURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let expectedExecutableURL = applicationURL.appendingPathComponent(
            "Contents/Library/LaunchServices/WhoSudodPAMInstaller"
        )
        guard applicationURL.pathExtension == "app",
              expectedExecutableURL.standardizedFileURL == executableURL.standardizedFileURL else {
            throw PAMInstallerFileError.missingPayload
        }
        return applicationURL
    }

    private func currentExecutableURL() throws -> URL {
        var capacity: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &capacity)
        var buffer = [CChar](repeating: 0, count: Int(capacity))
        guard _NSGetExecutablePath(&buffer, &capacity) == 0 else {
            throw PAMInstallerFileError.missingPayload
        }
        let pathBytes = buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:))
        return URL(fileURLWithPath: String(decoding: pathBytes, as: UTF8.self))
            .resolvingSymlinksInPath()
    }

    private func validatePayloadSignature(at url: URL, requirement requirementText: String) throws {
        var staticCode: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard status == errSecSuccess, let staticCode else {
            throw PAMInstallerFileError.invalidPayloadSignature(status)
        }

        var requirement: SecRequirement?
        status = SecRequirementCreateWithString(
            requirementText as CFString,
            [],
            &requirement
        )
        guard status == errSecSuccess, let requirement else {
            throw PAMInstallerFileError.invalidPayloadSignature(status)
        }

        status = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            requirement
        )
        guard status == errSecSuccess else {
            throw PAMInstallerFileError.invalidPayloadSignature(status)
        }
    }

    private func replacePayloadSetAtomically(
        module: OpenPayload,
        terminalReader: OpenPayload
    ) throws -> PayloadActivation {
        let parentDirectoryPath = (installationDirectoryPath as NSString)
            .deletingLastPathComponent
        try requireSafeDirectory(path: parentDirectoryPath, exactMode: 0o755)

        var stagingTemplate = Array(
            (parentDirectoryPath + "/.WhoSudod.stage.XXXXXX").utf8CString
        )
        guard mkdtemp(&stagingTemplate) != nil else {
            throw posixError("Create the staged PAM component directory")
        }
        let stagingDirectoryPath = String(
            decoding: stagingTemplate.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
        var shouldRemoveStagingDirectory = true
        defer {
            if shouldRemoveStagingDirectory {
                try? removeManagedPayloadDirectory(at: stagingDirectoryPath)
            }
        }

        guard chown(stagingDirectoryPath, 0, 0) == 0 else {
            throw posixError("Set staged PAM component directory ownership")
        }
        try installPayload(
            from: module,
            in: stagingDirectoryPath,
            fileName: (installedModulePath as NSString).lastPathComponent,
            temporaryName: ".pam_whosudod.so.XXXXXX",
            requirement: PAMIntegrationConstants.moduleSigningRequirement,
            componentName: "PAM module"
        )
        try installPayload(
            from: terminalReader,
            in: stagingDirectoryPath,
            fileName: (installedTerminalReaderPath as NSString).lastPathComponent,
            temporaryName: ".whosudod-pam-terminal-reader.XXXXXX",
            requirement: PAMIntegrationConstants.terminalReaderSigningRequirement,
            componentName: "terminal password reader"
        )
        guard chmod(stagingDirectoryPath, mode_t(0o755)) == 0 else {
            throw posixError("Set staged PAM component directory permissions")
        }
        try requireManagedPayloadDirectory(at: stagingDirectoryPath, requiresBothPayloads: true)
        try syncDirectory(path: stagingDirectoryPath)

        let activation: PayloadActivation
        var installedMetadata = stat()
        if lstat(installationDirectoryPath, &installedMetadata) == 0 {
            try requireManagedPayloadDirectory(
                at: installationDirectoryPath,
                requiresBothPayloads: false
            )
            guard renamex_np(
                stagingDirectoryPath,
                installationDirectoryPath,
                UInt32(RENAME_SWAP)
            ) == 0 else {
                throw posixError("Activate the PAM component set")
            }
            shouldRemoveStagingDirectory = false
            activation = PayloadActivation(previousDirectoryPath: stagingDirectoryPath)
        } else {
            guard errno == ENOENT else {
                throw posixError("Inspect the PAM component directory")
            }
            guard rename(stagingDirectoryPath, installationDirectoryPath) == 0 else {
                throw posixError("Activate the PAM component set")
            }
            shouldRemoveStagingDirectory = false
            activation = PayloadActivation(previousDirectoryPath: nil)
        }
        return activation
    }

    private func commitPayloadActivation(_ activation: PayloadActivation) {
        guard let previousDirectoryPath = activation.previousDirectoryPath else {
            return
        }
        try? removeManagedPayloadDirectory(at: previousDirectoryPath)
    }

    private func rollbackPayloadActivation(_ activation: PayloadActivation) throws {
        let parentDirectoryPath = (installationDirectoryPath as NSString)
            .deletingLastPathComponent
        guard let previousDirectoryPath = activation.previousDirectoryPath else {
            try removeManagedPayloadDirectory(at: installationDirectoryPath)
            return
        }

        try requireManagedPayloadDirectory(
            at: installationDirectoryPath,
            requiresBothPayloads: true
        )
        try requireManagedPayloadDirectory(
            at: previousDirectoryPath,
            requiresBothPayloads: false
        )
        guard renamex_np(
            previousDirectoryPath,
            installationDirectoryPath,
            UInt32(RENAME_SWAP)
        ) == 0 else {
            throw posixError("Restore the previous PAM component set")
        }
        try syncDirectory(path: parentDirectoryPath)

        // The active path is restored. Failure to remove the inactive new set
        // cannot leave sudo with a missing module.
        try? removeManagedPayloadDirectory(at: previousDirectoryPath)
    }

    private func installPayload(
        from source: OpenPayload,
        in directoryPath: String,
        fileName: String,
        temporaryName: String,
        requirement: String,
        componentName: String
    ) throws {
        let destinationPath = directoryPath + "/" + fileName
        try requireUnchangedPayload(source)
        guard lseek(source.descriptor, 0, SEEK_SET) == 0 else {
            throw posixError("Read the bundled \(componentName)")
        }

        try rejectSymlinkIfPresent(path: destinationPath)
        let template = directoryPath + "/" + temporaryName
        var templateBytes = Array(template.utf8CString)
        let temporaryFD = mkstemp(&templateBytes)
        guard temporaryFD >= 0 else { throw posixError("Create the temporary \(componentName)") }
        let temporaryPath = String(
            decoding: templateBytes.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
        var keepTemporaryFile = true
        defer {
            close(temporaryFD)
            if keepTemporaryFile { unlink(temporaryPath) }
        }

        guard fcopyfile(
            source.descriptor,
            temporaryFD,
            nil,
            copyfile_flags_t(COPYFILE_DATA)
        ) == 0 else {
            throw posixError("Copy the \(componentName)")
        }
        try requireUnchangedPayload(source)
        guard fchown(temporaryFD, 0, 0) == 0 else {
            throw posixError("Set \(componentName) ownership")
        }
        guard fchmod(temporaryFD, mode_t(0o555)) == 0 else {
            throw posixError("Set \(componentName) permissions")
        }
        try requireNoExtendedACL(fd: temporaryFD, path: temporaryPath)
        guard fsync(temporaryFD) == 0 else {
            throw posixError("Sync the \(componentName)")
        }
        try validatePayloadSignature(
            at: URL(fileURLWithPath: temporaryPath),
            requirement: requirement
        )
        guard rename(temporaryPath, destinationPath) == 0 else {
            throw posixError("Activate the \(componentName)")
        }
        keepTemporaryFile = false
        try syncDirectory(path: directoryPath)
    }

    private func openPayload(at path: String) throws -> OpenPayload {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw posixError("Open a bundled PAM component")
        }
        do {
            let metadata = try regularFileMetadata(fd: descriptor, path: path)
            let payload = OpenPayload(
                path: path,
                descriptor: descriptor,
                version: FileVersion(metadata)
            )
            try requireUnchangedPayload(payload)
            return payload
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func requireUnchangedPayload(_ payload: OpenPayload) throws {
        let descriptorMetadata = try regularFileMetadata(
            fd: payload.descriptor,
            path: payload.path
        )
        var pathMetadata = stat()
        guard lstat(payload.path, &pathMetadata) == 0,
              pathMetadata.st_mode & S_IFMT == S_IFREG,
              FileVersion(descriptorMetadata) == payload.version,
              FileVersion(pathMetadata) == payload.version else {
            throw PAMInstallerFileError.concurrentModification(payload.path)
        }
    }

    private func atomicReplaceConfiguration(
        with data: Data,
        replacing expected: FileSnapshot
    ) throws {
        let sourceFD = open(configurationPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard sourceFD >= 0 else { throw posixError("Open the sudo PAM configuration") }
        defer { close(sourceFD) }
        let sourceMetadata = try regularFileMetadata(fd: sourceFD, path: configurationPath)
        try requireRootOwnedReadOnlyFile(sourceMetadata, path: configurationPath)
        guard FileVersion(sourceMetadata) == expected.version else {
            throw PAMInstallerFileError.concurrentModification(configurationPath)
        }

        let directoryPath = (configurationPath as NSString).deletingLastPathComponent
        let temporaryTemplate = directoryPath + "/.sudo.whosudod.XXXXXX"
        var templateBytes = Array(temporaryTemplate.utf8CString)
        let temporaryFD = mkstemp(&templateBytes)
        guard temporaryFD >= 0 else { throw posixError("Create the temporary sudo PAM configuration") }
        let temporaryPath = String(
            decoding: templateBytes.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
        var keepTemporaryFile = true
        defer {
            close(temporaryFD)
            if keepTemporaryFile { unlink(temporaryPath) }
        }

        guard fchmod(temporaryFD, mode_t(0o600)) == 0 else {
            throw posixError("Protect the temporary sudo PAM configuration")
        }
        guard fcopyfile(
            sourceFD,
            temporaryFD,
            nil,
            copyfile_flags_t(COPYFILE_ACL | COPYFILE_XATTR)
        ) == 0 else {
            throw posixError("Copy sudo PAM configuration metadata")
        }
        try writeAll(data, to: temporaryFD)
        guard fchown(temporaryFD, expected.metadata.st_uid, expected.metadata.st_gid) == 0 else {
            throw posixError("Restore sudo PAM configuration ownership")
        }
        guard fchmod(temporaryFD, expected.metadata.st_mode & mode_t(0o7777)) == 0 else {
            throw posixError("Restore sudo PAM configuration permissions")
        }
        guard fsync(temporaryFD) == 0 else {
            throw posixError("Sync the sudo PAM configuration")
        }
        try requireNoExtendedACL(fd: temporaryFD, path: temporaryPath)
        try requireUnchangedFile(
            path: configurationPath,
            descriptor: sourceFD,
            expected: expected
        )
        guard rename(temporaryPath, configurationPath) == 0 else {
            throw posixError("Activate the sudo PAM configuration")
        }
        keepTemporaryFile = false
        // The atomic rename is the commit point. A later durability error must
        // not make the caller roll back payloads that the active PAM file uses.
        try? syncDirectory(path: directoryPath)
    }

    private func requireSafeDirectory(path: String, exactMode: mode_t? = nil) throws {
        var metadata = stat()
        guard lstat(path, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == 0,
              metadata.st_gid == 0,
              metadata.st_mode & mode_t(0o022) == 0 else {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        if let exactMode,
           metadata.st_mode & mode_t(0o7777) != exactMode {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        try requireNoExtendedACL(path: path)
    }

    private func hasExpectedInstallationDirectoryMetadata() throws -> Bool {
        var metadata = stat()
        guard lstat(installationDirectoryPath, &metadata) == 0 else {
            if errno == ENOENT {
                return false
            }
            throw posixError("Inspect the PAM installation directory")
        }
        try requireSafeDirectory(path: installationDirectoryPath)
        return metadata.st_mode & mode_t(0o7777) == mode_t(0o755)
    }

    private func rejectSymlinkIfPresent(path: String) throws {
        var metadata = stat()
        let result = lstat(path, &metadata)
        if result == 0 {
            guard metadata.st_mode & S_IFMT != S_IFLNK else {
                throw PAMInstallerFileError.unsafeFile(path)
            }
        } else if errno != ENOENT {
            throw posixError("Inspect the installed PAM component")
        }
    }

    private func hasExpectedInstalledPayloadMetadata(at path: String) throws -> Bool {
        var metadata = stat()
        guard lstat(path, &metadata) == 0 else {
            if errno == ENOENT { return false }
            throw posixError("Inspect the installed PAM component")
        }
        guard metadata.st_mode & S_IFMT == S_IFREG else {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        let hasExpectedMetadata = metadata.st_uid == 0
            && metadata.st_gid == 0
            && metadata.st_nlink == 1
            && metadata.st_mode & mode_t(0o777) == mode_t(0o555)
        if hasExpectedMetadata {
            try requireNoExtendedACL(path: path)
        }
        return hasExpectedMetadata
    }

    private func removeInstalledPayloads() throws {
        try removeManagedPayloadDirectory(at: installationDirectoryPath)
    }

    private func requireManagedPayloadDirectory(
        at directoryPath: String,
        requiresBothPayloads: Bool
    ) throws {
        try requireSafeDirectory(path: directoryPath)
        let moduleName = (installedModulePath as NSString).lastPathComponent
        let terminalReaderName = (installedTerminalReaderPath as NSString).lastPathComponent
        let allowedNames = Set([moduleName, terminalReaderName])
        let names = try FileManager.default.contentsOfDirectory(atPath: directoryPath)
        let nameSet = Set(names)
        guard nameSet.isSubset(of: allowedNames),
              !requiresBothPayloads || nameSet == allowedNames else {
            throw PAMInstallerFileError.unsafeFile(directoryPath)
        }

        for name in names {
            try requireRemovableInstalledPayload(at: directoryPath + "/" + name)
        }
    }

    private func removeManagedPayloadDirectory(at directoryPath: String) throws {
        var directoryMetadata = stat()
        if lstat(directoryPath, &directoryMetadata) != 0 {
            guard errno == ENOENT else {
                throw posixError("Inspect the PAM installation directory")
            }
            return
        }
        try requireManagedPayloadDirectory(at: directoryPath, requiresBothPayloads: false)
        try removeInstalledPayload(
            at: directoryPath + "/"
                + (installedTerminalReaderPath as NSString).lastPathComponent
        )
        try removeInstalledPayload(
            at: directoryPath + "/" + (installedModulePath as NSString).lastPathComponent
        )
        try syncDirectory(path: directoryPath)
        if rmdir(directoryPath) != 0, errno != ENOTEMPTY {
            throw posixError("Remove the PAM installation directory")
        }
        try syncDirectory(path: (directoryPath as NSString).deletingLastPathComponent)
    }

    private func removeInstalledPayload(at path: String) throws {
        var metadata = stat()
        if lstat(path, &metadata) != 0 {
            guard errno == ENOENT else { throw posixError("Inspect the installed PAM component") }
            return
        }
        try requireRemovableInstalledPayload(at: path, metadata: metadata)
        guard unlink(path) == 0 else {
            throw posixError("Remove the installed PAM component")
        }
    }

    private func requireRemovableInstalledPayload(at path: String) throws {
        var metadata = stat()
        guard lstat(path, &metadata) == 0 else {
            throw posixError("Inspect the installed PAM component")
        }
        try requireRemovableInstalledPayload(at: path, metadata: metadata)
    }

    private func requireRemovableInstalledPayload(
        at path: String,
        metadata: stat
    ) throws {
        guard metadata.st_mode & S_IFMT == S_IFREG else {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        guard metadata.st_uid == 0,
              metadata.st_gid == 0,
              metadata.st_nlink == 1,
              metadata.st_mode & mode_t(0o022) == 0 else {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        try requireNoExtendedACL(path: path)
    }

    private func secureRead(path: String) throws -> Data {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw posixError("Open \(path)") }
        defer { close(fd) }
        let metadata = try regularFileMetadata(fd: fd, path: path)
        if path == configurationPath {
            try requireRootOwnedReadOnlyFile(metadata, path: path)
        }
        try requireNoExtendedACL(fd: fd, path: path)

        return try readAll(from: fd, path: path)
    }

    private func secureFileSnapshot(path: String) throws -> FileSnapshot {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw posixError("Open \(path)") }
        defer { close(fd) }

        let metadata = try regularFileMetadata(fd: fd, path: path)
        try requireRootOwnedReadOnlyFile(metadata, path: path)
        try requireNoExtendedACL(fd: fd, path: path)
        let expectedVersion = FileVersion(metadata)
        let data = try readAll(from: fd, path: path)
        let finalMetadata = try regularFileMetadata(fd: fd, path: path)
        var pathMetadata = stat()
        guard lstat(path, &pathMetadata) == 0 else {
            throw posixError("Reinspect \(path)")
        }
        guard FileVersion(finalMetadata) == expectedVersion,
              FileVersion(pathMetadata) == expectedVersion else {
            throw PAMInstallerFileError.concurrentModification(path)
        }
        return FileSnapshot(
            data: data,
            metadata: metadata,
            version: expectedVersion
        )
    }

    private func requireUnchangedFile(
        path: String,
        descriptor: Int32,
        expected: FileSnapshot
    ) throws {
        let beforeRead = try regularFileMetadata(fd: descriptor, path: path)
        guard FileVersion(beforeRead) == expected.version,
              lseek(descriptor, 0, SEEK_SET) == 0 else {
            throw PAMInstallerFileError.concurrentModification(path)
        }
        let currentData = try readAll(from: descriptor, path: path)
        let afterRead = try regularFileMetadata(fd: descriptor, path: path)
        var pathMetadata = stat()
        guard lstat(path, &pathMetadata) == 0 else {
            throw posixError("Reinspect \(path)")
        }
        guard currentData == expected.data,
              FileVersion(afterRead) == expected.version,
              FileVersion(pathMetadata) == expected.version else {
            throw PAMInstallerFileError.concurrentModification(path)
        }
    }

    private func readAll(from fd: Int32, path: String) throws -> Data {
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw posixError("Read \(path)")
            }
            result.append(buffer, count: count)
        }
        return result
    }

    private func optionalSecureRead(path: String) throws -> Data? {
        var metadata = stat()
        if lstat(path, &metadata) != 0 {
            if errno == ENOENT { return nil }
            throw posixError("Inspect \(path)")
        }
        if path == installedModulePath || path == installedTerminalReaderPath {
            try requireSafeDirectory(path: installationDirectoryPath)
            guard try hasExpectedInstalledPayloadMetadata(at: path) else {
                throw PAMInstallerFileError.unsafeFile(path)
            }
        }
        return try secureRead(path: path)
    }

    private func requireRegularFile(fd: Int32, path: String) throws {
        _ = try regularFileMetadata(fd: fd, path: path)
    }

    private func regularFileMetadata(fd: Int32, path: String) throws -> stat {
        var metadata = stat()
        guard fstat(fd, &metadata) == 0 else { throw posixError("Inspect \(path)") }
        guard metadata.st_mode & S_IFMT == S_IFREG else {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        return metadata
    }

    private func requireRootOwnedReadOnlyFile(_ metadata: stat, path: String) throws {
        guard metadata.st_uid == 0,
              metadata.st_gid == 0,
              metadata.st_mode & mode_t(0o022) == 0 else {
            throw PAMInstallerFileError.unsafeFile(path)
        }
    }

    private func requireNoExtendedACL(path: String) throws {
        errno = 0
        guard let accessControlList = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return
            }
            throw posixError("Inspect access controls for \(path)")
        }
        defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
        try requireEmptyAccessControlList(accessControlList, path: path)
    }

    private func requireNoExtendedACL(fd: Int32, path: String) throws {
        errno = 0
        guard let accessControlList = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return
            }
            throw posixError("Inspect access controls for \(path)")
        }
        defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
        try requireEmptyAccessControlList(accessControlList, path: path)
    }

    private func requireEmptyAccessControlList(_ accessControlList: acl_t, path: String) throws {
        var entry: acl_entry_t?
        let result = acl_get_entry(
            accessControlList,
            Int32(ACL_FIRST_ENTRY.rawValue),
            &entry
        )
        if result == 1 {
            throw PAMInstallerFileError.unsafeFile(path)
        }
        if result < 0 {
            throw posixError("Inspect access controls for \(path)")
        }
    }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let count = Darwin.write(fd, baseAddress.advanced(by: offset), rawBuffer.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    throw posixError("Write the sudo PAM configuration")
                }
                offset += count
            }
        }
    }

    private func syncDirectory(path: String) throws {
        let fd = open(path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else { throw posixError("Open \(path)") }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw posixError("Sync \(path)") }
    }

    private func persistenceBarrier(path: String) throws {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw posixError("Open \(path)") }
        defer { close(fd) }
        guard fcntl(fd, F_BARRIERFSYNC) == 0 else {
            throw posixError("Order persistent changes for \(path)")
        }
    }

    private func posixError(_ operation: String) -> PAMInstallerFileError {
        PAMInstallerFileError.posix(operation: operation, code: errno)
    }
}

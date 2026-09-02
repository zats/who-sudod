import CryptoKit
import Darwin
import Foundation
import MachO
import Security

enum PAMInstallerFileError: LocalizedError {
    case installerIsNotRoot
    case unsupportedArchitecture
    case unsafeFile(String)
    case missingPayload
    case invalidPayloadSignature(OSStatus)
    case invalidApplicationSignature(OSStatus)
    case runningInstallerMismatch
    case concurrentModification(String)
    case posix(operation: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .installerIsNotRoot:
            "The PAM installer is not running as root."
        case .unsupportedArchitecture:
            "This PAM installer supports Apple silicon only."
        case .unsafeFile(let path):
            "The installer refused an unsafe file at \(path)."
        case .missingPayload:
            "A bundled PAM component is missing."
        case .invalidPayloadSignature(let status):
            "A bundled PAM component failed code-signature validation (\(status))."
        case .invalidApplicationSignature(let status):
            "The Who Sudo'd application failed code-signature validation (\(status))."
        case .runningInstallerMismatch:
            "The running PAM installer does not match the signed application on disk."
        case .concurrentModification(let path):
            "The installer stopped because \(path) changed during the operation. Try again."
        case .posix(let operation, let code):
            "\(operation) failed: \(String(cString: strerror(code)))."
        }
    }
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

    private let configurationPath = PAMIntegrationConstants.sudoConfigurationPath
    private let installationDirectoryPath = PAMIntegrationConstants.installationDirectoryPath
    private let installedModulePath = PAMIntegrationConstants.installedModulePath
    private let installedTerminalReaderPath = PAMIntegrationConstants.installedTerminalReaderPath

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

    func install() -> PAMIntegrationInspection {
        do {
            try validateRuntime()
            let modulePayloadURL = try embeddedPayloadURL(
                relativePath: PAMIntegrationConstants.embeddedModuleRelativePath
            )
            let terminalReaderPayloadURL = try embeddedPayloadURL(
                relativePath: PAMIntegrationConstants.embeddedTerminalReaderRelativePath
            )
            let modulePayload = try openPayload(at: modulePayloadURL.path)
            let terminalReaderPayload = try openPayload(at: terminalReaderPayloadURL.path)
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
            let deactivatedConfiguration = try PAMConfigurationEditor.uninstalling(
                from: initialConfiguration.data
            )
            if deactivatedConfiguration != initialConfiguration.data {
                try atomicReplaceConfiguration(
                    with: deactivatedConfiguration,
                    replacing: initialConfiguration
                )
            }
            try ensureInstallationDirectory()
            try installPayload(
                from: modulePayload,
                to: installedModulePath,
                temporaryName: ".pam_whosudod.so.XXXXXX",
                requirement: PAMIntegrationConstants.moduleSigningRequirement,
                componentName: "PAM module"
            )
            try installPayload(
                from: terminalReaderPayload,
                to: installedTerminalReaderPath,
                temporaryName: ".whosudod-pam-terminal-reader.XXXXXX",
                requirement: PAMIntegrationConstants.terminalReaderSigningRequirement,
                componentName: "terminal password reader"
            )
            try validateApplicationBundleForInstall(expectedURL: applicationURL)
            try requireUnchangedPayload(modulePayload)
            try requireUnchangedPayload(terminalReaderPayload)
            let currentConfiguration = try secureFileSnapshot(path: configurationPath)
            let activatedConfiguration = try PAMConfigurationEditor.installing(
                in: currentConfiguration.data
            )
            if activatedConfiguration != currentConfiguration.data {
                try atomicReplaceConfiguration(
                    with: activatedConfiguration,
                    replacing: currentConfiguration
                )
            }
            return inspect()
        } catch {
            return PAMIntegrationInspection(
                state: .unsupported,
                detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
        }
    }

    func uninstall() -> PAMIntegrationInspection {
        do {
            try validateRuntime()
            let configuration = try secureFileSnapshot(path: configurationPath)
            let updatedConfiguration = try PAMConfigurationEditor.uninstalling(
                from: configuration.data
            )
            if updatedConfiguration != configuration.data {
                try atomicReplaceConfiguration(
                    with: updatedConfiguration,
                    replacing: configuration
                )
            }
            try removeInstalledPayloads()
            return PAMIntegrationInspection(state: .notInstalled, detail: nil)
        } catch {
            return PAMIntegrationInspection(
                state: .unsupported,
                detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
        }
    }

    private func validateRuntime() throws {
        guard geteuid() == 0 else {
            throw PAMInstallerFileError.installerIsNotRoot
        }
        #if !arch(arm64)
        throw PAMInstallerFileError.unsupportedArchitecture
        #endif
        try requireSafeDirectory(path: "/etc/pam.d", exactMode: 0o755)
        try requireSafeDirectory(path: "/Library", exactMode: 0o755)
        try requireSafeDirectory(path: "/Library/Security", exactMode: 0o755)
    }

    private func embeddedPayloadURL(relativePath: String) throws -> URL {
        let payloadURL = try applicationBundleURL().appendingPathComponent(relativePath)
        guard FileManager.default.fileExists(atPath: payloadURL.path) else {
            throw PAMInstallerFileError.missingPayload
        }
        return payloadURL
    }

    @discardableResult
    private func validateApplicationBundleForInstall(expectedURL: URL? = nil) throws -> URL {
        let applicationURL = try applicationBundleURL()
        if let expectedURL,
           applicationURL.standardizedFileURL != expectedURL.standardizedFileURL {
            throw PAMInstallerFileError.runningInstallerMismatch
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
        let installerURL = applicationURL.appendingPathComponent(
            "Contents/Library/LaunchServices/WhoSudodPAMInstaller"
        )
        var installerCode: SecStaticCode?
        status = SecStaticCodeCreateWithPath(installerURL as CFURL, [], &installerCode)
        guard status == errSecSuccess, let installerCode else {
            throw PAMInstallerFileError.invalidApplicationSignature(status)
        }
        guard try codeDirectoryHash(for: runningStaticCode)
            == codeDirectoryHash(for: installerCode) else {
            throw PAMInstallerFileError.runningInstallerMismatch
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

    private func installPayload(
        from source: OpenPayload,
        to destinationPath: String,
        temporaryName: String,
        requirement: String,
        componentName: String
    ) throws {
        try requireUnchangedPayload(source)
        guard lseek(source.descriptor, 0, SEEK_SET) == 0 else {
            throw posixError("Read the bundled \(componentName)")
        }

        try rejectSymlinkIfPresent(path: destinationPath)
        let template = installationDirectoryPath + "/" + temporaryName
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
        try syncDirectory(path: installationDirectoryPath)
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
        try syncDirectory(path: directoryPath)
    }

    private func ensureInstallationDirectory() throws {
        try requireSafeDirectory(path: "/Library/Security")
        var metadata = stat()
        if lstat(installationDirectoryPath, &metadata) != 0 {
            guard errno == ENOENT else { throw posixError("Inspect the PAM installation directory") }
            guard mkdir(installationDirectoryPath, mode_t(0o755)) == 0 else {
                throw posixError("Create the PAM installation directory")
            }
            guard chown(installationDirectoryPath, 0, 0) == 0 else {
                throw posixError("Set PAM installation directory ownership")
            }
        }
        try requireSafeDirectory(path: installationDirectoryPath)
        guard chmod(installationDirectoryPath, mode_t(0o755)) == 0 else {
            throw posixError("Set PAM installation directory permissions")
        }
        try requireSafeDirectory(path: installationDirectoryPath, exactMode: 0o755)
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
        var directoryMetadata = stat()
        if lstat(installationDirectoryPath, &directoryMetadata) != 0 {
            guard errno == ENOENT else {
                throw posixError("Inspect the PAM installation directory")
            }
            return
        }
        try requireSafeDirectory(path: installationDirectoryPath)
        try removeInstalledPayload(at: installedTerminalReaderPath)
        try removeInstalledPayload(at: installedModulePath)
        try syncDirectory(path: installationDirectoryPath)
        if rmdir(installationDirectoryPath) != 0, errno != ENOTEMPTY {
            throw posixError("Remove the PAM installation directory")
        }
    }

    private func removeInstalledPayload(at path: String) throws {
        var metadata = stat()
        if lstat(path, &metadata) != 0 {
            guard errno == ENOENT else { throw posixError("Inspect the installed PAM component") }
            return
        }
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
        guard unlink(path) == 0 else {
            throw posixError("Remove the installed PAM component")
        }
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

    private func posixError(_ operation: String) -> PAMInstallerFileError {
        PAMInstallerFileError.posix(operation: operation, code: errno)
    }
}

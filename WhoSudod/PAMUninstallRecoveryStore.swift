import Darwin
import Foundation

protocol PAMUninstallRecoveryStoring {
    func load() throws -> PAMUninstallRecoveryPhase
    func save(_ phase: PAMUninstallRecoveryPhase) throws
}

enum PAMUninstallRecoveryStoreError: LocalizedError {
    case invalidValue
    case writeFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidValue:
            "The PAM change recovery file contains an invalid value."
        case .writeFailed(let detail):
            "The PAM change recovery state could not be saved. \(detail)"
        }
    }
}

final class FilePAMUninstallRecoveryStore: PAMUninstallRecoveryStoring {
    private let fileURL: URL
    private let fileManager: FileManager

    init(
        fileURL: URL = FilePAMUninstallRecoveryStore.defaultFileURL(),
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL.standardizedFileURL
        self.fileManager = fileManager
    }

    func load() throws -> PAMUninstallRecoveryPhase {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return .none
        }
        let data = try Data(contentsOf: fileURL, options: .mappedIfSafe)
        guard let value = String(data: data, encoding: .utf8),
              let phase = PAMUninstallRecoveryPhase(rawValue: value) else {
            throw PAMUninstallRecoveryStoreError.invalidValue
        }
        return phase
    }

    func save(_ phase: PAMUninstallRecoveryPhase) throws {
        do {
            try saveAtomically(Data(phase.rawValue.utf8))
        } catch let error as PAMUninstallRecoveryStoreError {
            throw error
        } catch {
            throw PAMUninstallRecoveryStoreError.writeFailed(error.localizedDescription)
        }
    }

    private func saveAtomically(_ data: Data) throws {
        let directoryURL = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        let temporaryURL = directoryURL.appendingPathComponent(
            ".\(fileURL.lastPathComponent).\(UUID().uuidString).tmp"
        )
        var temporaryExists = true
        defer {
            if temporaryExists {
                try? fileManager.removeItem(at: temporaryURL)
            }
        }

        var descriptor = Darwin.open(
            temporaryURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else {
            throw posixError(action: "The temporary file could not be opened")
        }
        defer {
            if descriptor >= 0 {
                Darwin.close(descriptor)
            }
        }

        try data.withUnsafeBytes { bytes in
            guard var cursor = bytes.baseAddress else {
                return
            }
            var remaining = bytes.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, cursor, remaining)
                if written < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw posixError(action: "The temporary file could not be written")
                }
                guard written > 0 else {
                    throw PAMUninstallRecoveryStoreError.writeFailed(
                        "The temporary file write made no progress."
                    )
                }
                cursor = cursor.advanced(by: written)
                remaining -= written
            }
        }

        guard Darwin.fsync(descriptor) == 0 else {
            throw posixError(action: "The temporary file could not be synced")
        }
        guard Darwin.close(descriptor) == 0 else {
            descriptor = -1
            throw posixError(action: "The temporary file could not be closed")
        }
        descriptor = -1

        let renameResult = temporaryURL.path.withCString { sourcePath in
            fileURL.path.withCString { destinationPath in
                Darwin.rename(sourcePath, destinationPath)
            }
        }
        guard renameResult == 0 else {
            throw posixError(action: "The recovery file could not be replaced")
        }
        temporaryExists = false

        let directoryDescriptor = Darwin.open(
            directoryURL.path,
            O_RDONLY | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else {
            throw posixError(action: "The recovery directory could not be opened")
        }
        defer { Darwin.close(directoryDescriptor) }
        guard Darwin.fsync(directoryDescriptor) == 0 else {
            throw posixError(action: "The recovery directory could not be synced")
        }
    }

    private func posixError(action: String) -> PAMUninstallRecoveryStoreError {
        let code = errno
        let detail = String(cString: strerror(code))
        return .writeFailed("\(action): \(detail).")
    }

    private static func defaultFileURL(
        fileManager: FileManager = .default
    ) -> URL {
        let applicationSupportURL = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support", isDirectory: true)
        return applicationSupportURL
            .appendingPathComponent("Who Sudo'd", isDirectory: true)
            .appendingPathComponent("pam-uninstall-recovery-phase")
    }
}

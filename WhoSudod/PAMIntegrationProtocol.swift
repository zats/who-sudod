import Foundation

enum PAMIntegrationConstants {
    static let machServiceName = "com.zats.WhoSudo.PAMInstaller"
    static let launchDaemonPlistName = "com.zats.WhoSudo.PAMInstaller.plist"
    static let applicationSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let installerSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo.PAMInstaller\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let moduleSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo.PAM\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let terminalReaderSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo.PAMTerminalReader\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""

    static let sudoConfigurationPath = "/etc/pam.d/sudo"
    static let installationDirectoryPath = "/Library/Security/WhoSudod"
    static let installedModulePath = "/Library/Security/WhoSudod/pam_whosudod.so"
    static let installedTerminalReaderPath = "/Library/Security/WhoSudod/whosudod-pam-terminal-reader"
    static let embeddedModuleRelativePath = "Contents/Library/PAMModules/pam_whosudod.so"
    static let embeddedTerminalReaderRelativePath = "Contents/Library/PAMModules/whosudod-pam-terminal-reader"

    static let ownedOfferConfigurationLine = "auth       optional       /Library/Security/WhoSudod/pam_whosudod.so       whosudod_offer_v1"
    static let ownedRestoreConfigurationLine = "auth       optional       /Library/Security/WhoSudod/pam_whosudod.so       whosudod_restore_v1"
}

enum PAMIntegrationStateCode: Int, Sendable {
    case notInstalled = 0
    case installed = 1
    case needsRepair = 2
    case unsupported = 3
}

struct PAMIntegrationInspection: Equatable, Sendable {
    let state: PAMIntegrationStateCode
    let detail: String?
}

@objc protocol PAMInstallerXPCProtocol {
    func status(reply: @escaping (Int, String?) -> Void)
    func install(reply: @escaping (Int, String?) -> Void)
    func uninstall(reply: @escaping (Int, String?) -> Void)
}

enum PAMConfigurationError: LocalizedError, Equatable {
    case invalidEncoding
    case missingPasswordAnchor
    case ambiguousPasswordAnchor
    case unsupportedPasswordAnchorOptions
    case foreignModuleReference

    var errorDescription: String? {
        switch self {
        case .invalidEncoding:
            "The sudo PAM configuration is not valid UTF-8."
        case .missingPasswordAnchor:
            "The sudo PAM configuration has no active Open Directory password entry."
        case .ambiguousPasswordAnchor:
            "The sudo PAM configuration has more than one active Open Directory password entry."
        case .unsupportedPasswordAnchorOptions:
            "The Open Directory password entry has options that Who Sudo'd cannot safely preserve."
        case .foreignModuleReference:
            "An unowned PAM entry already refers to the Who Sudo'd module path."
        }
    }
}

struct PAMConfigurationEditor {
    private struct Line {
        let fullRange: Range<Int>
        let contentRange: Range<Int>
        let terminator: [UInt8]
    }

    private static let ownedOfferLineBytes = Array(
        PAMIntegrationConstants.ownedOfferConfigurationLine.utf8
    )
    private static let ownedRestoreLineBytes = Array(
        PAMIntegrationConstants.ownedRestoreConfigurationLine.utf8
    )
    private static let modulePath = PAMIntegrationConstants.installedModulePath

    static func inspect(
        configuration: Data,
        moduleExists: Bool,
        moduleMatchesPayload: Bool,
        terminalReaderExists: Bool,
        terminalReaderMatchesPayload: Bool
    ) -> PAMIntegrationInspection {
        do {
            let analysis = try analyze(Array(configuration))
            if analysis.ownedOfferLineIndices.isEmpty,
               analysis.ownedRestoreLineIndices.isEmpty,
               !moduleExists,
               !terminalReaderExists {
                return PAMIntegrationInspection(state: .notInstalled, detail: nil)
            }

            let isCorrectlyPlaced = analysis.ownedOfferLineIndices.count == 1
                && analysis.ownedRestoreLineIndices.count == 1
                && analysis.ownedOfferLineIndices[0] + 1 == analysis.anchorIndex
                && analysis.ownedRestoreLineIndices[0] == analysis.anchorIndex + 1
            if isCorrectlyPlaced,
               moduleExists,
               moduleMatchesPayload,
               terminalReaderExists,
               terminalReaderMatchesPayload {
                return PAMIntegrationInspection(state: .installed, detail: nil)
            }

            return PAMIntegrationInspection(
                state: .needsRepair,
                detail: repairDetail(
                    ownedOfferLineCount: analysis.ownedOfferLineIndices.count,
                    ownedRestoreLineCount: analysis.ownedRestoreLineIndices.count,
                    isCorrectlyPlaced: isCorrectlyPlaced,
                    moduleExists: moduleExists,
                    moduleMatchesPayload: moduleMatchesPayload,
                    terminalReaderExists: terminalReaderExists,
                    terminalReaderMatchesPayload: terminalReaderMatchesPayload
                )
            )
        } catch {
            return PAMIntegrationInspection(
                state: .unsupported,
                detail: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
        }
    }

    static func installing(in configuration: Data) throws -> Data {
        let original = Array(configuration)
        _ = try analyze(original)
        let withoutOwnedLines = try removingOwnedLines(from: original)
        let analysis = try analyze(withoutOwnedLines)
        let anchor = analysis.lines[analysis.anchorIndex]
        let terminator = preferredTerminator(for: anchor, in: analysis.lines)

        var updated = withoutOwnedLines
        var restoreInsertion: [UInt8]
        if anchor.terminator.isEmpty {
            restoreInsertion = terminator + ownedRestoreLineBytes
        } else {
            restoreInsertion = ownedRestoreLineBytes + anchor.terminator
        }
        updated.insert(contentsOf: restoreInsertion, at: anchor.fullRange.upperBound)

        var offerInsertion = ownedOfferLineBytes
        offerInsertion.append(contentsOf: terminator)
        updated.insert(contentsOf: offerInsertion, at: anchor.fullRange.lowerBound)
        return Data(updated)
    }

    static func uninstalling(from configuration: Data) throws -> Data {
        let bytes = Array(configuration)
        try validateForRemoval(bytes)
        return Data(try removingOwnedLines(from: bytes))
    }

    private struct Analysis {
        let lines: [Line]
        let anchorIndex: Int
        let ownedOfferLineIndices: [Int]
        let ownedRestoreLineIndices: [Int]
    }

    private static func analyze(_ bytes: [UInt8]) throws -> Analysis {
        guard String(bytes: bytes, encoding: .utf8) != nil else {
            throw PAMConfigurationError.invalidEncoding
        }

        let parsedLines = lines(in: bytes)
        var anchorIndices: [Int] = []
        var ownedOfferLineIndices: [Int] = []
        var ownedRestoreLineIndices: [Int] = []

        for (index, line) in parsedLines.enumerated() {
            let content = Array(bytes[line.contentRange])
            if content == ownedOfferLineBytes {
                ownedOfferLineIndices.append(index)
                continue
            }
            if content == ownedRestoreLineBytes {
                ownedRestoreLineIndices.append(index)
                continue
            }

            guard let text = String(bytes: content, encoding: .utf8) else {
                throw PAMConfigurationError.invalidEncoding
            }
            let trimmed = text.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else {
                continue
            }

            let tokens = trimmed.split(whereSeparator: \Character.isWhitespace).map(String.init)
            if tokens.count >= 3,
               tokens[0] == "auth",
               tokens[1] == "required",
               tokens[2] == "pam_opendirectory.so" {
                guard tokens.count == 3 else {
                    throw PAMConfigurationError.unsupportedPasswordAnchorOptions
                }
                anchorIndices.append(index)
            }

            if tokens.contains(modulePath) {
                throw PAMConfigurationError.foreignModuleReference
            }
        }

        guard !anchorIndices.isEmpty else {
            throw PAMConfigurationError.missingPasswordAnchor
        }
        guard anchorIndices.count == 1 else {
            throw PAMConfigurationError.ambiguousPasswordAnchor
        }

        return Analysis(
            lines: parsedLines,
            anchorIndex: anchorIndices[0],
            ownedOfferLineIndices: ownedOfferLineIndices,
            ownedRestoreLineIndices: ownedRestoreLineIndices
        )
    }

    private static func removingOwnedLines(from bytes: [UInt8]) throws -> [UInt8] {
        let parsedLines = lines(in: bytes)
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)

        for line in parsedLines {
            let content = Array(bytes[line.contentRange])
            if content != ownedOfferLineBytes,
               content != ownedRestoreLineBytes {
                result.append(contentsOf: bytes[line.fullRange])
            }
        }
        return result
    }

    private static func validateForRemoval(_ bytes: [UInt8]) throws {
        guard String(bytes: bytes, encoding: .utf8) != nil else {
            throw PAMConfigurationError.invalidEncoding
        }
        for line in lines(in: bytes) {
            let content = Array(bytes[line.contentRange])
            if content == ownedOfferLineBytes || content == ownedRestoreLineBytes {
                continue
            }
            guard let text = String(bytes: content, encoding: .utf8) else {
                throw PAMConfigurationError.invalidEncoding
            }
            let trimmed = text.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            let tokens = trimmed.split(whereSeparator: \Character.isWhitespace).map(String.init)
            if tokens.contains(modulePath) {
                throw PAMConfigurationError.foreignModuleReference
            }
        }
    }

    private static func lines(in bytes: [UInt8]) -> [Line] {
        guard !bytes.isEmpty else { return [] }

        var result: [Line] = []
        var start = 0
        while start < bytes.count {
            var cursor = start
            while cursor < bytes.count, bytes[cursor] != 0x0A {
                cursor += 1
            }

            let hasLineFeed = cursor < bytes.count
            let contentEnd = hasLineFeed && cursor > start && bytes[cursor - 1] == 0x0D
                ? cursor - 1
                : cursor
            let fullEnd = hasLineFeed ? cursor + 1 : cursor
            let terminator = Array(bytes[contentEnd..<fullEnd])
            result.append(
                Line(
                    fullRange: start..<fullEnd,
                    contentRange: start..<contentEnd,
                    terminator: terminator
                )
            )
            start = fullEnd
        }
        return result
    }

    private static func preferredTerminator(for anchor: Line, in lines: [Line]) -> [UInt8] {
        if !anchor.terminator.isEmpty {
            return anchor.terminator
        }
        return lines.lazy.map(\.terminator).first(where: { !$0.isEmpty }) ?? [0x0A]
    }

    private static func repairDetail(
        ownedOfferLineCount: Int,
        ownedRestoreLineCount: Int,
        isCorrectlyPlaced: Bool,
        moduleExists: Bool,
        moduleMatchesPayload: Bool,
        terminalReaderExists: Bool,
        terminalReaderMatchesPayload: Bool
    ) -> String {
        if ownedOfferLineCount != 1 || ownedRestoreLineCount != 1 {
            return "An owned sudo PAM entry is missing or duplicated."
        }
        if !isCorrectlyPlaced {
            return "The owned sudo PAM entry is not directly before the password entry."
        }
        if !moduleExists {
            return "The installed PAM module is missing."
        }
        if !moduleMatchesPayload {
            return "The installed PAM module does not match this version of Who Sudo'd."
        }
        if !terminalReaderExists {
            return "The installed terminal password reader is missing."
        }
        if !terminalReaderMatchesPayload {
            return "The installed terminal password reader does not match this version of Who Sudo'd."
        }
        return "The PAM integration needs repair."
    }
}

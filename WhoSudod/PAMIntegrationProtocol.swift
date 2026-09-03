import CryptoKit
import Foundation
import Security

enum PAMIntegrationConstants {
    static let machServiceName = "com.zats.WhoSudo.PAMInstaller"
    static let launchDaemonPlistName = "com.zats.WhoSudo.PAMInstaller.plist"
    static let applicationSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let helperSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo.PAMInstaller\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let moduleSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo.PAM\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let terminalReaderSigningRequirement = "anchor apple generic and identifier \"com.zats.WhoSudo.PAMTerminalReader\" and certificate leaf[subject.OU] = \"5KE88HWMKJ\""
    static let modificationAuthorizationRight = "system.privilege.admin"

    static let sudoConfigurationPath = "/etc/pam.d/sudo"
    static let installationDirectoryPath = "/Library/Security/WhoSudod"
    static let installedModulePath = "/Library/Security/WhoSudod/pam_whosudod.so"
    static let installedTerminalReaderPath = "/Library/Security/WhoSudod/whosudod-pam-terminal-reader"
    static let embeddedModuleRelativePath = "Contents/Library/PAMModules/pam_whosudod.so"
    static let embeddedTerminalReaderRelativePath = "Contents/Library/PAMModules/whosudod-pam-terminal-reader"
    static let embeddedHelperRelativePath = "Contents/Library/LaunchServices/WhoSudodPAMInstaller"

    static let ownedOfferConfigurationLine = "auth       optional       /Library/Security/WhoSudod/pam_whosudod.so       whosudod_offer_v1"
    static let ownedRestoreConfigurationLine = "auth       optional       /Library/Security/WhoSudod/pam_whosudod.so       whosudod_restore_v1"
}

struct PAMHelperBuildIdentity: Equatable, Sendable {
    let applicationCodeDirectoryHash: Data
    let helperCodeDirectoryHash: Data
    let token: Data

    init(applicationCodeDirectoryHash: Data, helperCodeDirectoryHash: Data) {
        self.applicationCodeDirectoryHash = applicationCodeDirectoryHash
        self.helperCodeDirectoryHash = helperCodeDirectoryHash
        token = Self.encodedToken(
            applicationHash: applicationCodeDirectoryHash,
            helperHash: helperCodeDirectoryHash
        )
    }

    func matches(token expectedToken: Data) -> Bool {
        guard token.count == expectedToken.count else {
            return false
        }
        var difference: UInt8 = 0
        for (actual, expected) in zip(token, expectedToken) {
            difference |= actual ^ expected
        }
        return difference == 0
    }

    func exactApplicationSigningRequirement() throws -> String {
        try exactSigningRequirement(
            base: PAMIntegrationConstants.applicationSigningRequirement,
            codeDirectoryHash: applicationCodeDirectoryHash
        )
    }

    func exactHelperSigningRequirement() throws -> String {
        try exactSigningRequirement(
            base: PAMIntegrationConstants.helperSigningRequirement,
            codeDirectoryHash: helperCodeDirectoryHash
        )
    }

    static func embedded(in applicationBundleURL: URL) throws -> Self {
        let applicationURL = applicationBundleURL.standardizedFileURL
        let helperURL = applicationURL.appendingPathComponent(
            PAMIntegrationConstants.embeddedHelperRelativePath
        )
        let applicationCode = try validatedStaticCode(
            at: applicationURL,
            requirement: PAMIntegrationConstants.applicationSigningRequirement,
            checksNestedCode: true
        )
        let helperCode = try validatedStaticCode(
            at: helperURL,
            requirement: PAMIntegrationConstants.helperSigningRequirement,
            checksNestedCode: false
        )
        return Self(
            applicationCodeDirectoryHash: try codeDirectoryHash(for: applicationCode),
            helperCodeDirectoryHash: try codeDirectoryHash(for: helperCode)
        )
    }

    static func currentHelper() throws -> Self {
        var runningCode: SecCode?
        var status = SecCodeCopySelf([], &runningCode)
        guard status == errSecSuccess, let runningCode else {
            throw PAMHelperBuildIdentityError.cannotReadCode(status)
        }

        var helperCode: SecStaticCode?
        status = SecCodeCopyStaticCode(runningCode, [], &helperCode)
        guard status == errSecSuccess, let helperCode else {
            throw PAMHelperBuildIdentityError.cannotReadCode(status)
        }
        try validate(
            helperCode,
            requirement: PAMIntegrationConstants.helperSigningRequirement,
            checksNestedCode: false
        )

        var helperURL: CFURL?
        status = SecCodeCopyPath(helperCode, [], &helperURL)
        guard status == errSecSuccess, let helperURL else {
            throw PAMHelperBuildIdentityError.cannotReadCode(status)
        }
        let executableURL = (helperURL as URL).standardizedFileURL
        let applicationURL = executableURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let expectedExecutableURL = applicationURL.appendingPathComponent(
            PAMIntegrationConstants.embeddedHelperRelativePath
        )
        guard applicationURL.pathExtension == "app",
              expectedExecutableURL.standardizedFileURL == executableURL else {
            throw PAMHelperBuildIdentityError.unexpectedHelperLocation
        }

        let applicationCode = try validatedStaticCode(
            at: applicationURL,
            requirement: PAMIntegrationConstants.applicationSigningRequirement,
            checksNestedCode: true
        )
        return Self(
            applicationCodeDirectoryHash: try codeDirectoryHash(for: applicationCode),
            helperCodeDirectoryHash: try codeDirectoryHash(for: helperCode)
        )
    }

    private static func validatedStaticCode(
        at url: URL,
        requirement: String,
        checksNestedCode: Bool
    ) throws -> SecStaticCode {
        var code: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(url as CFURL, [], &code)
        guard status == errSecSuccess, let code else {
            throw PAMHelperBuildIdentityError.cannotReadCode(status)
        }
        try validate(code, requirement: requirement, checksNestedCode: checksNestedCode)
        return code
    }

    private static func validate(
        _ code: SecStaticCode,
        requirement requirementText: String,
        checksNestedCode: Bool
    ) throws {
        var requirement: SecRequirement?
        var status = SecRequirementCreateWithString(
            requirementText as CFString,
            [],
            &requirement
        )
        guard status == errSecSuccess, let requirement else {
            throw PAMHelperBuildIdentityError.cannotReadCode(status)
        }
        var rawFlags = kSecCSStrictValidate | kSecCSRestrictSymlinks
        if checksNestedCode {
            rawFlags |= kSecCSCheckNestedCode
        }
        status = SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: rawFlags),
            requirement
        )
        guard status == errSecSuccess else {
            throw PAMHelperBuildIdentityError.invalidSignature(status)
        }
    }

    private static func codeDirectoryHash(for code: SecStaticCode) throws -> Data {
        var information: CFDictionary?
        let status = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        )
        guard status == errSecSuccess,
              let dictionary = information as? [String: Any],
              let hash = dictionary[kSecCodeInfoUnique as String] as? Data else {
            throw PAMHelperBuildIdentityError.cannotReadCode(status)
        }
        return hash
    }

    private static func encodedToken(applicationHash: Data, helperHash: Data) -> Data {
        var input = Data("WhoSudod.PAMHelperBuild.v1".utf8)
        append(applicationHash, to: &input)
        append(helperHash, to: &input)
        return Data(SHA256.hash(data: input))
    }

    private func exactSigningRequirement(
        base: String,
        codeDirectoryHash: Data
    ) throws -> String {
        guard !codeDirectoryHash.isEmpty else {
            throw PAMHelperBuildIdentityError.invalidCodeDirectoryHash
        }
        let hash = codeDirectoryHash.map { String(format: "%02x", $0) }.joined()
        let text = "(\(base)) and cdhash H\"\(hash)\""
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(text as CFString, [], &requirement)
        guard status == errSecSuccess, requirement != nil else {
            throw PAMHelperBuildIdentityError.invalidRequirement(status)
        }
        return text
    }

    private static func append(_ value: Data, to token: inout Data) {
        var length = UInt32(value.count).bigEndian
        withUnsafeBytes(of: &length) { token.append(contentsOf: $0) }
        token.append(value)
    }
}

enum PAMHelperBuildIdentityError: LocalizedError, Equatable {
    case cannotReadCode(OSStatus)
    case invalidSignature(OSStatus)
    case invalidRequirement(OSStatus)
    case invalidCodeDirectoryHash
    case unexpectedHelperLocation
    case mismatch

    var errorDescription: String? {
        switch self {
        case .cannotReadCode(let status):
            "The PAM helper build identity could not be read (\(status))."
        case .invalidSignature(let status):
            "The PAM helper build has an invalid signature (\(status))."
        case .invalidRequirement(let status):
            "The exact PAM helper identity requirement is invalid (\(status))."
        case .invalidCodeDirectoryHash:
            "The PAM helper build has no CodeDirectory hash."
        case .unexpectedHelperLocation:
            "The PAM helper is not inside the current application."
        case .mismatch:
            "The registered PAM helper does not match this application build."
        }
    }
}

enum PAMIntegrationStateCode: Int, Sendable {
    case notInstalled = 0
    case installed = 1
    case needsRepair = 2
    case unsupported = 3
    case removalOnly = 4
}

enum PAMHelperReplyCode {
    static let transportFailure = -1
}

struct PAMIntegrationInspection: Equatable, Sendable {
    let state: PAMIntegrationStateCode
    let detail: String?
}

@objc protocol PAMInstallerXPCProtocol {
    func buildIdentity(reply: @escaping (Data?, String?) -> Void)
    func status(reply: @escaping (Int, String?) -> Void)
    func install(
        authorization: Data,
        expectedBuildIdentity: Data,
        reply: @escaping (Int, String?, String?) -> Void
    )
    func uninstall(
        authorization: Data,
        expectedBuildIdentity: Data,
        reply: @escaping (Int, String?, String?) -> Void
    )
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
        let bytes = Array(configuration)
        let hasOwnedArtifacts = moduleExists
            || terminalReaderExists
            || hasOwnedPayloadReference(in: configuration)
        do {
            let analysis = try analyze(bytes)
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
            let state: PAMIntegrationStateCode
            if hasOwnedArtifacts, canSafelyRemoveOwnedArtifacts(from: bytes) {
                state = .removalOnly
            } else {
                state = .unsupported
            }
            return PAMIntegrationInspection(
                state: state,
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

    static func hasOwnedPayloadReference(in configuration: Data) -> Bool {
        containsOwnedConfigurationLine(in: Array(configuration))
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

    private static func containsOwnedConfigurationLine(in bytes: [UInt8]) -> Bool {
        lines(in: bytes).contains { line in
            let content = Array(bytes[line.contentRange])
            return content == ownedOfferLineBytes || content == ownedRestoreLineBytes
        }
    }

    private static func canSafelyRemoveOwnedArtifacts(from bytes: [UInt8]) -> Bool {
        do {
            try validateForRemoval(bytes)
            return true
        } catch {
            return false
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

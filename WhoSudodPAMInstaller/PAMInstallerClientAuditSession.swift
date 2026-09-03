import Darwin
import Foundation
import OSLog

struct PAMInstallerClientAuditSession: Equatable {
    let userIdentifier: uid_t
    let sessionIdentifier: au_asid_t
}

enum PAMInstallerClientAuditSessionError: LocalizedError, Equatable {
    case unavailable
    case invalidSession
    case invalidUser
    case lookupFailed(Int32)
    case sessionMismatch
    case userMismatch
    case differentSession
    case currentSessionFailed(Int32)
    case adoptionFailed(Int32)
    case verificationFailed

    var errorDescription: String? {
        switch self {
        case .unavailable:
            "The PAM helper could not identify the application audit session."
        case .invalidSession:
            "The PAM helper rejected an invalid application audit session."
        case .invalidUser:
            "The PAM helper rejected a system audit session."
        case .lookupFailed(let code):
            "The PAM helper could not identify the application audit session: \(String(cString: strerror(code)))."
        case .sessionMismatch:
            "The PAM helper resolved a different application audit session."
        case .userMismatch:
            "The PAM helper rejected an audit session for a different user."
        case .differentSession:
            "The PAM helper is already serving a different login session."
        case .currentSessionFailed(let code):
            "The PAM helper could not read its audit session: \(String(cString: strerror(code)))."
        case .adoptionFailed(let code):
            "The PAM helper could not join the application audit session: \(String(cString: strerror(code)))."
        case .verificationFailed:
            "The PAM helper could not verify the application audit session."
        }
    }
}

struct SystemPAMInstallerClientAuditSessionAdopter {
    typealias SessionResolver = (au_asid_t) throws -> auditinfo_addr
    typealias CurrentSessionReader = () throws -> auditinfo_addr
    typealias SessionSetter = (auditinfo_addr) throws -> Void

    private let resolveSession: SessionResolver
    private let readCurrentSession: CurrentSessionReader
    private let setSession: SessionSetter

    init(
        resolveSession: SessionResolver? = nil,
        readCurrentSession: CurrentSessionReader? = nil,
        setSession: SessionSetter? = nil
    ) {
        self.resolveSession = resolveSession ?? Self.resolveSystemSession
        self.readCurrentSession = readCurrentSession ?? Self.readSystemSession
        self.setSession = setSession ?? Self.setSystemSession
    }

    func adopt(_ client: PAMInstallerClientAuditSession) throws {
        guard client.userIdentifier > 0 else {
            throw PAMInstallerClientAuditSessionError.invalidUser
        }
        guard client.sessionIdentifier > 0 else {
            throw PAMInstallerClientAuditSessionError.invalidSession
        }

        let session = try resolveSession(client.sessionIdentifier)
        guard session.ai_asid == client.sessionIdentifier else {
            throw PAMInstallerClientAuditSessionError.sessionMismatch
        }
        guard session.ai_auid == client.userIdentifier else {
            throw PAMInstallerClientAuditSessionError.userMismatch
        }

        let currentSession = try readCurrentSession()
        if currentSession.ai_asid == client.sessionIdentifier {
            guard currentSession.ai_auid == client.userIdentifier else {
                throw PAMInstallerClientAuditSessionError.userMismatch
            }
            return
        }
        // launchd can start a daemon in a numbered session that has no audit
        // user yet. AU_DEFAUDITID is (uid_t)-1; its C macro is not imported
        // into Swift. The unassigned user, not ASID zero, identifies this state.
        guard currentSession.ai_auid == uid_t.max else {
            Logger(subsystem: "com.zats.WhoSudo", category: "PAMAuditSession").error(
                "Cannot adopt client audit session: helper user=\(currentSession.ai_auid, privacy: .public) session=\(currentSession.ai_asid, privacy: .public), client user=\(client.userIdentifier, privacy: .public) session=\(client.sessionIdentifier, privacy: .public)"
            )
            throw PAMInstallerClientAuditSessionError.differentSession
        }

        try setSession(session)
        let adoptedSession = try readCurrentSession()
        guard adoptedSession.ai_asid == client.sessionIdentifier,
              adoptedSession.ai_auid == client.userIdentifier else {
            throw PAMInstallerClientAuditSessionError.verificationFailed
        }
    }

    private static func resolveSystemSession(
        sessionIdentifier: au_asid_t
    ) throws -> auditinfo_addr {
        var session = auditinfo_addr()
        session.ai_asid = sessionIdentifier
        guard audit_get_sinfo_addr(
            &session,
            MemoryLayout<auditinfo_addr>.size
        ) == 0 else {
            let code = errno
            throw PAMInstallerClientAuditSessionError.lookupFailed(code)
        }
        return session
    }

    private static func readSystemSession() throws -> auditinfo_addr {
        var session = auditinfo_addr()
        guard getaudit_addr(
            &session,
            Int32(MemoryLayout<auditinfo_addr>.size)
        ) == 0 else {
            let code = errno
            throw PAMInstallerClientAuditSessionError.currentSessionFailed(code)
        }
        return session
    }

    private static func setSystemSession(_ session: auditinfo_addr) throws {
        var session = session
        guard setaudit_addr(
            &session,
            Int32(MemoryLayout<auditinfo_addr>.size)
        ) == 0 else {
            let code = errno
            throw PAMInstallerClientAuditSessionError.adoptionFailed(code)
        }
    }
}

final class PAMInstallerClientAuditSessionGate {
    typealias Adopter = (PAMInstallerClientAuditSession) throws -> Void

    private let adopter: Adopter
    private var adoptedSession: PAMInstallerClientAuditSession?

    init(
        adopter: @escaping Adopter = {
            try SystemPAMInstallerClientAuditSessionAdopter().adopt($0)
        }
    ) {
        self.adopter = adopter
    }

    func perform<Result>(
        client: PAMInstallerClientAuditSession,
        operation: () throws -> Result
    ) throws -> Result {
        if let adoptedSession {
            guard adoptedSession == client else {
                throw PAMInstallerClientAuditSessionError.differentSession
            }
        } else {
            try adopter(client)
            adoptedSession = client
        }
        return try operation()
    }
}

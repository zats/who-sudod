import Foundation

struct AuthenticationPromptSessionKey: Hashable, Sendable {
    let windowIdentity: AuthenticationWindowIdentity
    let presenterProcessID: pid_t
    let surfaceKind: AuthenticationSurfaceKind

    init(window: AuthenticationWindowSnapshot) {
        windowIdentity = window.identity
        presenterProcessID = window.processID
        surfaceKind = window.surfaceKind
    }
}

struct AuthenticationPromptSession: Equatable, Sendable {
    let firstSeenAt: Date
    let promptSequence: Int
    var processSnapshot: AuthenticationProcessSnapshot
    var hasAttributedSnapshot: Bool
    var lastSeenAt: Date
    var consecutiveMissingObservations: Int
}

struct AuthenticationPromptSessionStore {
    private(set) var sessions: [AuthenticationPromptSessionKey: AuthenticationPromptSession] = [:]
    private var nextPromptSequence = 1
    private let capacity: Int

    var accessibilityWindowIdentities: [AuthenticationWindowIdentity] {
        sessions.keys.compactMap { key in
            guard case .accessibility = key.windowIdentity else {
                return nil
            }
            return key.windowIdentity
        }
    }

    init(capacity: Int = 32) {
        precondition(capacity > 0)
        self.capacity = capacity
    }

    mutating func activate(
        window: AuthenticationWindowSnapshot,
        at date: Date
    ) -> AuthenticationPromptSession {
        let key = AuthenticationPromptSessionKey(window: window)
        if var session = sessions[key] {
            session.lastSeenAt = date
            session.consecutiveMissingObservations = 0
            sessions[key] = session
            return session
        }

        let session = AuthenticationPromptSession(
            firstSeenAt: date,
            promptSequence: nextPromptSequence,
            processSnapshot: .pending,
            hasAttributedSnapshot: false,
            lastSeenAt: date,
            consecutiveMissingObservations: 0
        )
        nextPromptSequence += 1
        sessions[key] = session
        removeOldestSessionsIfNeeded(preserving: key)
        return session
    }

    mutating func touch(window: AuthenticationWindowSnapshot, at date: Date) {
        let key = AuthenticationPromptSessionKey(window: window)
        guard var session = sessions[key] else {
            return
        }
        session.lastSeenAt = date
        session.consecutiveMissingObservations = 0
        sessions[key] = session
    }

    mutating func update(
        window: AuthenticationWindowSnapshot,
        processSnapshot: AuthenticationProcessSnapshot,
        at date: Date
    ) {
        let key = AuthenticationPromptSessionKey(window: window)
        var session = sessions[key] ?? activate(window: window, at: date)
        session.processSnapshot = processSnapshot
        session.hasAttributedSnapshot = true
        session.lastSeenAt = date
        session.consecutiveMissingObservations = 0
        sessions[key] = session
    }

    mutating func transfer(
        from oldWindow: AuthenticationWindowSnapshot,
        to newWindow: AuthenticationWindowSnapshot,
        at date: Date
    ) -> AuthenticationPromptSession {
        let oldKey = AuthenticationPromptSessionKey(window: oldWindow)
        let newKey = AuthenticationPromptSessionKey(window: newWindow)
        guard oldKey != newKey else {
            return activate(window: newWindow, at: date)
        }

        if var existingDestination = sessions[newKey],
           existingDestination.hasAttributedSnapshot {
            existingDestination.lastSeenAt = date
            existingDestination.consecutiveMissingObservations = 0
            sessions[newKey] = existingDestination
            return existingDestination
        }

        guard var session = sessions.removeValue(forKey: oldKey) else {
            return activate(window: newWindow, at: date)
        }
        session.lastSeenAt = date
        session.consecutiveMissingObservations = 0
        sessions[newKey] = session
        return session
    }

    mutating func observeVisibleCoreGraphicsWindows(
        _ windows: [AuthenticationWindowSnapshot],
        at date: Date,
        requiredMissingObservations: Int = 3,
        preserving preservedKeys: Set<AuthenticationPromptSessionKey> = []
    ) {
        precondition(requiredMissingObservations > 0)
        let visibleKeys = Set(windows.map(AuthenticationPromptSessionKey.init(window:)))

        for key in Array(sessions.keys) {
            guard case .coreGraphics = key.windowIdentity,
                  var session = sessions[key] else {
                continue
            }
            if visibleKeys.contains(key) {
                session.lastSeenAt = date
                session.consecutiveMissingObservations = 0
                sessions[key] = session
                continue
            }
            guard !preservedKeys.contains(key) else {
                continue
            }

            session.consecutiveMissingObservations += 1
            if session.consecutiveMissingObservations >= requiredMissingObservations {
                sessions.removeValue(forKey: key)
            } else {
                sessions[key] = session
            }
        }

        for window in windows where sessions[AuthenticationPromptSessionKey(window: window)] == nil {
            _ = activate(window: window, at: date)
        }
    }

    mutating func observeVisibleAccessibilityWindows(
        _ windows: [AuthenticationWindowSnapshot],
        at date: Date,
        requiredMissingObservations: Int = 3,
        preserving preservedKeys: Set<AuthenticationPromptSessionKey> = []
    ) {
        precondition(requiredMissingObservations > 0)
        let visibleKeys = Set(windows.map(AuthenticationPromptSessionKey.init(window:)))

        for key in Array(sessions.keys) {
            guard case .accessibility = key.windowIdentity,
                  var session = sessions[key] else {
                continue
            }
            if visibleKeys.contains(key) {
                session.lastSeenAt = date
                session.consecutiveMissingObservations = 0
                sessions[key] = session
                continue
            }
            guard !preservedKeys.contains(key) else {
                continue
            }

            session.consecutiveMissingObservations += 1
            if session.consecutiveMissingObservations >= requiredMissingObservations {
                sessions.removeValue(forKey: key)
            } else {
                sessions[key] = session
            }
        }
    }

    mutating func remove(window: AuthenticationWindowSnapshot) {
        sessions.removeValue(forKey: AuthenticationPromptSessionKey(window: window))
    }

    mutating func remove(key: AuthenticationPromptSessionKey) {
        sessions.removeValue(forKey: key)
    }

    mutating func removeAll() {
        sessions.removeAll(keepingCapacity: false)
        nextPromptSequence = 1
    }

    func session(for window: AuthenticationWindowSnapshot) -> AuthenticationPromptSession? {
        sessions[AuthenticationPromptSessionKey(window: window)]
    }

    private mutating func removeOldestSessionsIfNeeded(
        preserving preservedKey: AuthenticationPromptSessionKey
    ) {
        while sessions.count > capacity {
            guard let oldestKey = sessions
                .filter({ $0.key != preservedKey })
                .min(by: { $0.value.lastSeenAt < $1.value.lastSeenAt })?
                .key else {
                return
            }
            sessions.removeValue(forKey: oldestKey)
        }
    }
}

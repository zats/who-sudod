import Darwin
import Foundation

final class PAMInstallerLifecycle: @unchecked Sendable {
    static let launchdThrottleInterval: TimeInterval = 10
    static let minimumProcessLifetime: TimeInterval = 15
    static let idleGracePeriod: TimeInterval = 1

    typealias Clock = @Sendable () -> TimeInterval
    typealias Scheduler = @Sendable (
        TimeInterval,
        @escaping @Sendable () -> Void
    ) -> Void
    typealias Termination = @Sendable () -> Void

    private let lock = NSLock()
    private let clock: Clock
    private let scheduler: Scheduler
    private let terminate: Termination
    private let startedAt: TimeInterval
    private var connections: [ObjectIdentifier: NSXPCConnection] = [:]
    private var activeOperations = 0
    private var exitGeneration: UInt64 = 0
    private var terminationRequested = false

    init(
        clock: Clock? = nil,
        scheduler: Scheduler? = nil,
        terminate: Termination? = nil
    ) {
        precondition(Self.minimumProcessLifetime > Self.launchdThrottleInterval)

        let clock = clock ?? { ProcessInfo.processInfo.systemUptime }
        self.clock = clock
        self.scheduler = scheduler ?? { delay, action in
            DispatchQueue.main.asyncAfter(
                deadline: .now() + delay,
                execute: action
            )
        }
        self.terminate = terminate ?? { exit(EXIT_SUCCESS) }
        startedAt = clock()
        scheduleExitIfIdle()
    }

    func add(_ connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard !terminationRequested else {
                return false
            }
            exitGeneration &+= 1
            connections[ObjectIdentifier(connection)] = connection
            return true
        }
    }

    func remove(_ connection: NSXPCConnection) {
        _ = lock.withLock {
            connections.removeValue(forKey: ObjectIdentifier(connection))
        }
        scheduleExitIfIdle()
    }

    func beginOperation() -> Bool {
        lock.withLock {
            guard !terminationRequested else {
                return false
            }
            exitGeneration &+= 1
            activeOperations += 1
            return true
        }
    }

    func endOperation() {
        lock.withLock {
            if activeOperations > 0 {
                activeOperations -= 1
            }
        }
        scheduleExitIfIdle()
    }

    private func scheduleExitIfIdle() {
        let request = lock.withLock { () -> (UInt64, TimeInterval)? in
            guard !terminationRequested,
                  connections.isEmpty,
                  activeOperations == 0
            else {
                return nil
            }
            exitGeneration &+= 1
            let generation = exitGeneration
            let elapsed = max(0, clock() - startedAt)
            let minimumLifetimeRemaining = max(
                0,
                Self.minimumProcessLifetime - elapsed
            )
            return (
                generation,
                max(Self.idleGracePeriod, minimumLifetimeRemaining)
            )
        }
        guard let (generation, delay) = request else {
            return
        }
        scheduler(delay) { [weak self] in
            self?.exitIfStillIdle(generation: generation)
        }
    }

    private func exitIfStillIdle(generation: UInt64) {
        let shouldTerminate = lock.withLock {
            guard !terminationRequested,
                  exitGeneration == generation,
                  connections.isEmpty,
                  activeOperations == 0
            else {
                return false
            }
            terminationRequested = true
            return true
        }
        if shouldTerminate {
            terminate()
        }
    }
}

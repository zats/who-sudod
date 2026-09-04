import Foundation
import XCTest

final class PAMInstallerLifecycleTests: XCTestCase {
    func testMinimumRuntimeExceedsDeclaredLaunchdThrottle() throws {
        XCTAssertGreaterThan(
            PAMInstallerLifecycle.minimumProcessLifetime,
            PAMInstallerLifecycle.launchdThrottleInterval
        )

        let sourceRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let plistURL = sourceRoot.appendingPathComponent(
            "WhoSudodPAMInstaller/com.zats.WhoSudo.PAMInstaller.plist"
        )
        let data = try Data(contentsOf: plistURL)
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [String: Any]
        )
        XCTAssertEqual(
            plist["ThrottleInterval"] as? Int,
            Int(PAMInstallerLifecycle.launchdThrottleInterval)
        )
    }

    func testInitialIdleExitWaitsForMinimumRuntime() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()

        XCTAssertEqual(
            harness.scheduler.delays,
            [PAMInstallerLifecycle.minimumProcessLifetime]
        )
        harness.scheduler.runNext()
        XCTAssertEqual(harness.termination.count, 1)
        withExtendedLifetime(lifecycle) {}
    }

    func testConnectionCancelsPendingExitAndLastConnectionSchedulesAnother() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.Lifecycle.Connection",
            options: []
        )

        XCTAssertTrue(lifecycle.add(connection))
        harness.scheduler.runNext()
        XCTAssertEqual(harness.termination.count, 0)

        lifecycle.remove(connection)
        XCTAssertEqual(harness.scheduler.delays.count, 1)
        harness.scheduler.runNext()
        XCTAssertEqual(harness.termination.count, 1)
    }

    func testActiveOperationCancelsPendingExit() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()

        XCTAssertTrue(lifecycle.beginOperation())
        harness.scheduler.runNext()
        XCTAssertEqual(harness.termination.count, 0)

        lifecycle.endOperation()
        harness.scheduler.runNext()
        XCTAssertEqual(harness.termination.count, 1)
    }

    func testExitNeverOccursWhileAnOperationIsActive() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.Lifecycle.Operation",
            options: []
        )

        XCTAssertTrue(lifecycle.add(connection))
        lifecycle.remove(connection)
        XCTAssertTrue(lifecycle.beginOperation())
        harness.scheduler.runAll()
        XCTAssertEqual(harness.termination.count, 0)

        lifecycle.endOperation()
        harness.scheduler.runNext()
        XCTAssertEqual(harness.termination.count, 1)
    }

    func testIdleGraceAppliesAfterMinimumRuntime() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.Lifecycle.Grace",
            options: []
        )

        XCTAssertTrue(lifecycle.add(connection))
        harness.clock.value = PAMInstallerLifecycle.minimumProcessLifetime + 5
        lifecycle.remove(connection)

        XCTAssertEqual(
            harness.scheduler.delays.last,
            PAMInstallerLifecycle.idleGracePeriod
        )
    }

    func testTerminationIsRequestedOnlyOnce() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()
        let action = harness.scheduler.takeNext()

        action?()
        action?()

        XCTAssertEqual(harness.termination.count, 1)
        withExtendedLifetime(lifecycle) {}
    }

    func testTerminationCommitRejectsNewConnectionsAndOperations() {
        let harness = LifecycleHarness()
        let lifecycle = harness.makeLifecycle()
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.Lifecycle.Terminated",
            options: []
        )

        harness.scheduler.runNext()

        XCTAssertEqual(harness.termination.count, 1)
        XCTAssertFalse(lifecycle.add(connection))
        XCTAssertFalse(lifecycle.beginOperation())
    }
}

private final class LifecycleHarness: @unchecked Sendable {
    let clock = LifecycleTestClock()
    let scheduler = LifecycleTestScheduler()
    let termination = LifecycleTerminationRecorder()

    func makeLifecycle() -> PAMInstallerLifecycle {
        PAMInstallerLifecycle(
            clock: { [clock] in clock.value },
            scheduler: { [scheduler] delay, action in
                scheduler.schedule(after: delay, action: action)
            },
            terminate: { [termination] in termination.record() }
        )
    }
}

private final class LifecycleTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue: TimeInterval = 0

    var value: TimeInterval {
        get { lock.withLock { storedValue } }
        set { lock.withLock { storedValue = newValue } }
    }
}

private final class LifecycleTestScheduler: @unchecked Sendable {
    private struct Job: @unchecked Sendable {
        let delay: TimeInterval
        let action: @Sendable () -> Void
    }

    private let lock = NSLock()
    private var jobs: [Job] = []

    var delays: [TimeInterval] {
        lock.withLock { jobs.map(\.delay) }
    }

    func schedule(
        after delay: TimeInterval,
        action: @escaping @Sendable () -> Void
    ) {
        lock.withLock {
            jobs.append(Job(delay: delay, action: action))
        }
    }

    func takeNext() -> (@Sendable () -> Void)? {
        lock.withLock {
            guard !jobs.isEmpty else {
                return nil
            }
            return jobs.removeFirst().action
        }
    }

    func runNext() {
        takeNext()?()
    }

    func runAll() {
        while let action = takeNext() {
            action()
        }
    }
}

private final class LifecycleTerminationRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storedCount = 0

    var count: Int {
        lock.withLock { storedCount }
    }

    func record() {
        lock.withLock {
            storedCount += 1
        }
    }
}

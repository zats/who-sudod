import XCTest

final class PAMMutationTransactionTests: XCTestCase {
    private enum PayloadSet: Equatable {
        case absent
        case partial
        case complete(Int)
    }

    private struct PublishedState: Equatable {
        var payloads: PayloadSet
        var configurationReferencesPayloads: Bool

        var isSafe: Bool {
            !configurationReferencesPayloads || {
                if case .complete = payloads { return true }
                return false
            }()
        }
    }

    private enum InjectedFailure: Error {
        case boundary
    }

    private enum InstallBoundary: String, CaseIterable {
        case activatePayloads
        case validatePayloads
        case persistPayloads
        case validateConfiguration
        case commitConfiguration
    }

    private final class InstallOperations: PAMInstallTransactionOperations {
        typealias PayloadActivation = PayloadSet

        private(set) var state: PublishedState
        private(set) var previousPayloads: PayloadSet?
        private(set) var calls: [InstallBoundary] = []
        private(set) var snapshots: [PublishedState] = []
        var failure: InstallBoundary?
        var leavePreviousPayloadsAfterCommit = false
        var failToRestorePreviousPayloads = false
        private(set) var activationWasPersisted = false

        init(state: PublishedState, failure: InstallBoundary? = nil) {
            self.state = state
            self.failure = failure
        }

        func activateCompletePayloadSet() throws -> PayloadSet {
            calls.append(.activatePayloads)
            if failure == .activatePayloads {
                // A partially prepared staging directory is never the active path.
                snapshots.append(state)
                throw InjectedFailure.boundary
            }
            let previous = state.payloads
            previousPayloads = previous
            state.payloads = .complete(2)
            recordPublishedState()
            return previous
        }

        func validateActivatedPayloadSet() throws {
            try reach(.validatePayloads)
        }

        func persistActivatedPayloadSet() throws {
            try reach(.persistPayloads)
            activationWasPersisted = true
        }

        func validateConfigurationBeforeCommit() throws {
            try reach(.validateConfiguration)
        }

        func commitConfigurationReferencingPayloads() throws {
            calls.append(.commitConfiguration)
            if failure == .commitConfiguration {
                snapshots.append(state)
                throw InjectedFailure.boundary
            }
            XCTAssertEqual(state.payloads, .complete(2))
            state.configurationReferencesPayloads = true
            recordPublishedState()
        }

        func discardPreviousPayloadSet(after activation: PayloadSet) {
            guard !leavePreviousPayloadsAfterCommit else { return }
            previousPayloads = nil
        }

        func recoverFromPrecommitFailure(
            after activation: PayloadSet,
            activationWasPersisted: Bool
        ) {
            guard !failToRestorePreviousPayloads else {
                recordPublishedState()
                return
            }
            if state.configurationReferencesPayloads {
                if activationWasPersisted {
                    previousPayloads = nil
                }
                recordPublishedState()
                return
            }
            state.payloads = activation
            previousPayloads = nil
            recordPublishedState()
        }

        private func reach(_ boundary: InstallBoundary) throws {
            calls.append(boundary)
            snapshots.append(state)
            if failure == boundary {
                throw InjectedFailure.boundary
            }
        }

        private func recordPublishedState() {
            snapshots.append(state)
            XCTAssertTrue(state.isSafe)
        }
    }

    private enum UninstallBoundary: String, CaseIterable {
        case commitConfiguration
        case persistConfiguration
        case validateRemoval
        case removePayloads
    }

    private final class UninstallOperations: PAMUninstallTransactionOperations {
        private(set) var state: PublishedState
        private(set) var calls: [UninstallBoundary] = []
        private(set) var snapshots: [PublishedState] = []
        var failure: UninstallBoundary?

        init(state: PublishedState, failure: UninstallBoundary? = nil) {
            self.state = state
            self.failure = failure
        }

        func commitConfigurationWithoutPayloadReferences() throws {
            calls.append(.commitConfiguration)
            if failure == .commitConfiguration {
                snapshots.append(state)
                throw InjectedFailure.boundary
            }
            state.configurationReferencesPayloads = false
            recordPublishedState()
        }

        func persistConfigurationWithoutPayloadReferences() throws {
            try reach(.persistConfiguration)
        }

        func validatePayloadRemoval() throws {
            calls.append(.validateRemoval)
            snapshots.append(state)
            if failure == .validateRemoval {
                // Model an outside privileged writer that restores a reference
                // after our atomic configuration commit. Validation must stop
                // before either payload is removed.
                state.configurationReferencesPayloads = true
                recordPublishedState()
                throw InjectedFailure.boundary
            }
        }

        func removePayloadSet() throws {
            calls.append(.removePayloads)
            XCTAssertFalse(state.configurationReferencesPayloads)
            if failure == .removePayloads {
                // Removing two files can stop after the first unlink. This is
                // safe because the configuration commit already removed both
                // references.
                state.payloads = .partial
                recordPublishedState()
                throw InjectedFailure.boundary
            }
            state.payloads = .absent
            recordPublishedState()
        }

        private func reach(_ boundary: UninstallBoundary) throws {
            calls.append(boundary)
            snapshots.append(state)
            if failure == boundary {
                throw InjectedFailure.boundary
            }
        }

        private func recordPublishedState() {
            snapshots.append(state)
            XCTAssertTrue(state.isSafe)
        }
    }

    func testInstallFailureAtEveryBoundaryPreservesSafePublishedState() {
        let startingStates = [
            PublishedState(payloads: .absent, configurationReferencesPayloads: false),
            PublishedState(payloads: .complete(1), configurationReferencesPayloads: true),
        ]

        for initialState in startingStates {
            for boundary in InstallBoundary.allCases {
                let operations = InstallOperations(state: initialState, failure: boundary)

                XCTAssertThrowsError(
                    try PAMInstallTransactionCoordinator(operations: operations).run(),
                    "Expected injected install failure at \(boundary.rawValue)"
                )
                if initialState.configurationReferencesPayloads,
                   boundary != .activatePayloads {
                    XCTAssertEqual(operations.state.payloads, .complete(2))
                    XCTAssertTrue(operations.state.configurationReferencesPayloads)
                } else {
                    XCTAssertEqual(operations.state, initialState)
                }
                if initialState.configurationReferencesPayloads,
                   boundary == .validatePayloads || boundary == .persistPayloads {
                    XCTAssertEqual(operations.previousPayloads, initialState.payloads)
                } else {
                    XCTAssertNil(operations.previousPayloads)
                }
                XCTAssertTrue(operations.snapshots.allSatisfy(\.isSafe))
                XCTAssertEqual(operations.calls.last, boundary)
            }
        }
    }

    func testInstallSuccessUsesTheRequiredCommitOrder() throws {
        let operations = InstallOperations(
            state: PublishedState(payloads: .absent, configurationReferencesPayloads: false)
        )

        try PAMInstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(operations.calls, InstallBoundary.allCases)
        XCTAssertEqual(
            operations.state,
            PublishedState(payloads: .complete(2), configurationReferencesPayloads: true)
        )
        XCTAssertNil(operations.previousPayloads)
        XCTAssertTrue(operations.snapshots.allSatisfy(\.isSafe))
    }

    func testInstallCleanupCanRemainIncompleteAfterCommitWithoutBreakingPAM() throws {
        let operations = InstallOperations(
            state: PublishedState(payloads: .complete(1), configurationReferencesPayloads: true)
        )
        operations.leavePreviousPayloadsAfterCommit = true

        try PAMInstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(operations.state.payloads, .complete(2))
        XCTAssertTrue(operations.state.configurationReferencesPayloads)
        XCTAssertEqual(operations.previousPayloads, .complete(1))
        XCTAssertTrue(operations.state.isSafe)
    }

    func testInstallRollbackFailureCannotExposePartialPayloads() {
        let operations = InstallOperations(
            state: PublishedState(payloads: .absent, configurationReferencesPayloads: false),
            failure: .persistPayloads
        )
        operations.failToRestorePreviousPayloads = true

        XCTAssertThrowsError(
            try PAMInstallTransactionCoordinator(operations: operations).run()
        )

        XCTAssertEqual(operations.state.payloads, .complete(2))
        XCTAssertFalse(operations.state.configurationReferencesPayloads)
        XCTAssertTrue(operations.state.isSafe)
    }

    func testPrebarrierRepairFailureRetainsOldDirectoryForCrashRecovery() {
        for boundary in [InstallBoundary.validatePayloads, .persistPayloads] {
            let operations = InstallOperations(
                state: PublishedState(
                    payloads: .complete(1),
                    configurationReferencesPayloads: true
                ),
                failure: boundary
            )

            XCTAssertThrowsError(
                try PAMInstallTransactionCoordinator(operations: operations).run()
            )

            XCTAssertFalse(operations.activationWasPersisted)
            XCTAssertEqual(operations.previousPayloads, .complete(1))
            XCTAssertEqual(operations.state.payloads, .complete(2))
            XCTAssertTrue(operations.state.isSafe)
        }
    }

    func testRepairFailureKeepsCompletePayloadsForExistingConfigurationReferences() {
        let repairState = PublishedState(
            payloads: .partial,
            configurationReferencesPayloads: true
        )
        let postActivationBoundaries = InstallBoundary.allCases.filter {
            $0 != .activatePayloads
        }

        for boundary in postActivationBoundaries {
            let operations = InstallOperations(state: repairState, failure: boundary)

            XCTAssertThrowsError(
                try PAMInstallTransactionCoordinator(operations: operations).run()
            )

            XCTAssertEqual(operations.state.payloads, .complete(2))
            XCTAssertTrue(operations.state.configurationReferencesPayloads)
            XCTAssertTrue(operations.state.isSafe)
        }
    }

    func testUninstallFailureAtEveryBoundaryPreservesSafePublishedState() {
        let initialState = PublishedState(
            payloads: .complete(1),
            configurationReferencesPayloads: true
        )

        for boundary in UninstallBoundary.allCases {
            let operations = UninstallOperations(state: initialState, failure: boundary)

            XCTAssertThrowsError(
                try PAMUninstallTransactionCoordinator(operations: operations).run(),
                "Expected injected uninstall failure at \(boundary.rawValue)"
            )
            XCTAssertTrue(operations.state.isSafe)
            XCTAssertTrue(operations.snapshots.allSatisfy(\.isSafe))
            XCTAssertEqual(operations.calls.last, boundary)

            if boundary == .commitConfiguration {
                XCTAssertEqual(operations.state, initialState)
            } else if boundary == .validateRemoval {
                XCTAssertEqual(operations.state, initialState)
            } else {
                XCTAssertFalse(operations.state.configurationReferencesPayloads)
            }
        }
    }

    func testUninstallSuccessUsesTheRequiredCommitOrder() throws {
        let operations = UninstallOperations(
            state: PublishedState(
                payloads: .complete(1),
                configurationReferencesPayloads: true
            )
        )

        try PAMUninstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(operations.calls, UninstallBoundary.allCases)
        XCTAssertEqual(
            operations.state,
            PublishedState(payloads: .absent, configurationReferencesPayloads: false)
        )
        XCTAssertTrue(operations.snapshots.allSatisfy(\.isSafe))
    }

    func testRemovalOnlyStateCanCleanUpPartialPayloads() throws {
        let operations = UninstallOperations(
            state: PublishedState(payloads: .partial, configurationReferencesPayloads: false)
        )

        try PAMUninstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(
            operations.state,
            PublishedState(payloads: .absent, configurationReferencesPayloads: false)
        )
    }
}

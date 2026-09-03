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
        var durableConfigurationReferencesPayloads: Bool
        var stagedPayloads: [PayloadSet]
        var hasTemporaryConfiguration: Bool

        init(
            payloads: PayloadSet,
            configurationReferencesPayloads: Bool,
            durableConfigurationReferencesPayloads: Bool? = nil,
            stagedPayloads: [PayloadSet] = [],
            hasTemporaryConfiguration: Bool = false
        ) {
            self.payloads = payloads
            self.configurationReferencesPayloads = configurationReferencesPayloads
            self.durableConfigurationReferencesPayloads =
                durableConfigurationReferencesPayloads
                ?? configurationReferencesPayloads
            self.stagedPayloads = stagedPayloads
            self.hasTemporaryConfiguration = hasTemporaryConfiguration
        }

        var isSafe: Bool {
            !(configurationReferencesPayloads
                || durableConfigurationReferencesPayloads) || {
                if case .complete = payloads { return true }
                return false
            }()
        }

        var hasManagedResidue: Bool {
            !stagedPayloads.isEmpty || hasTemporaryConfiguration
        }

        mutating func recoverInterruptedMutation() {
            durableConfigurationReferencesPayloads =
                configurationReferencesPayloads
            hasTemporaryConfiguration = false
            if configurationReferencesPayloads {
                if case .complete = payloads {
                    stagedPayloads.removeAll()
                }
            } else {
                payloads = .absent
                stagedPayloads.removeAll()
            }
        }
    }

    private enum InjectedFailure: Error {
        case boundary
    }

    private enum InstallBoundary: String, CaseIterable {
        case recoverInterruptedMutation
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
        private let startedSafe: Bool

        init(state: PublishedState, failure: InstallBoundary? = nil) {
            self.state = state
            self.failure = failure
            startedSafe = state.isSafe
        }

        func recoverInterruptedMutation() throws {
            calls.append(.recoverInterruptedMutation)
            snapshots.append(state)
            if failure == .recoverInterruptedMutation {
                throw InjectedFailure.boundary
            }
            state.recoverInterruptedMutation()
            snapshots.append(state)
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
            if previous != .absent {
                state.stagedPayloads.append(previous)
            }
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
            state.durableConfigurationReferencesPayloads = true
            recordPublishedState()
        }

        func discardPreviousPayloadSet(after activation: PayloadSet) {
            guard !leavePreviousPayloadsAfterCommit else { return }
            previousPayloads = nil
            state.stagedPayloads.removeAll()
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
                    state.stagedPayloads.removeAll()
                }
                recordPublishedState()
                return
            }
            state.payloads = activation
            previousPayloads = nil
            state.stagedPayloads.removeAll()
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
            if startedSafe {
                XCTAssertTrue(state.isSafe)
            }
        }
    }

    private enum UninstallBoundary: String, CaseIterable {
        case recoverInterruptedMutation
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
        private let startedSafe: Bool

        init(state: PublishedState, failure: UninstallBoundary? = nil) {
            self.state = state
            self.failure = failure
            startedSafe = state.isSafe
        }

        func recoverInterruptedMutation() throws {
            calls.append(.recoverInterruptedMutation)
            snapshots.append(state)
            if failure == .recoverInterruptedMutation {
                throw InjectedFailure.boundary
            }
            state.recoverInterruptedMutation()
            snapshots.append(state)
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
            state.durableConfigurationReferencesPayloads = false
            recordPublishedState()
        }

        func validatePayloadRemoval() throws {
            calls.append(.validateRemoval)
            snapshots.append(state)
            if failure == .validateRemoval {
                // Model an outside privileged writer that restores a reference
                // after our atomic configuration commit. Validation must stop
                // before either payload is removed.
                state.configurationReferencesPayloads = true
                state.durableConfigurationReferencesPayloads = true
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
            state.stagedPayloads.removeAll()
            state.hasTemporaryConfiguration = false
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
            if startedSafe {
                XCTAssertTrue(state.isSafe)
            }
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
                   boundary != .recoverInterruptedMutation,
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
        XCTAssertEqual(operations.state.stagedPayloads, [.complete(1)])
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
            $0 != .recoverInterruptedMutation && $0 != .activatePayloads
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

            if boundary == .recoverInterruptedMutation
                || boundary == .commitConfiguration {
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

    func testRestartedInstallRemovesAnInterruptedStagingSet() throws {
        let interruptedState = PublishedState(
            payloads: .absent,
            configurationReferencesPayloads: false,
            stagedPayloads: [.partial],
            hasTemporaryConfiguration: true
        )
        let operations = InstallOperations(state: interruptedState)

        try PAMInstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(
            operations.snapshots[1],
            PublishedState(
                payloads: .absent,
                configurationReferencesPayloads: false
            )
        )
        XCTAssertEqual(
            operations.state,
            PublishedState(
                payloads: .complete(2),
                configurationReferencesPayloads: true
            )
        )
        XCTAssertFalse(operations.state.hasManagedResidue)
    }

    func testRestartedFreshInstallRemovesUnreferencedActivePayloads() throws {
        let interruptedState = PublishedState(
            payloads: .complete(2),
            configurationReferencesPayloads: false,
            stagedPayloads: [.complete(1)]
        )
        let operations = InstallOperations(state: interruptedState)

        try PAMInstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(
            operations.snapshots[1],
            PublishedState(
                payloads: .absent,
                configurationReferencesPayloads: false
            )
        )
        XCTAssertEqual(operations.state.payloads, .complete(2))
        XCTAssertTrue(operations.state.configurationReferencesPayloads)
        XCTAssertFalse(operations.state.hasManagedResidue)
    }

    func testRestartedRepairKeepsReferencedCompletePayloadsAndRemovesStaging() throws {
        let interruptedState = PublishedState(
            payloads: .complete(2),
            configurationReferencesPayloads: true,
            durableConfigurationReferencesPayloads: false,
            stagedPayloads: [.partial],
            hasTemporaryConfiguration: true
        )
        let operations = InstallOperations(state: interruptedState)

        try PAMInstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(
            operations.snapshots[1],
            PublishedState(
                payloads: .complete(2),
                configurationReferencesPayloads: true
            )
        )
        XCTAssertEqual(operations.state.payloads, .complete(2))
        XCTAssertTrue(operations.state.configurationReferencesPayloads)
        XCTAssertFalse(operations.state.hasManagedResidue)
    }

    func testRestartedUninstallRemovesPayloadsAfterConfigurationCommit() throws {
        let operations = UninstallOperations(
            state: PublishedState(
                payloads: .complete(2),
                configurationReferencesPayloads: false,
                durableConfigurationReferencesPayloads: true,
                stagedPayloads: [.complete(1)],
                hasTemporaryConfiguration: true
            )
        )

        try PAMUninstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(
            operations.snapshots[1],
            PublishedState(
                payloads: .absent,
                configurationReferencesPayloads: false
            )
        )
        XCTAssertEqual(
            operations.state,
            PublishedState(
                payloads: .absent,
                configurationReferencesPayloads: false
            )
        )
    }

    func testRestartedUninstallRemovesAResumablePartialPayloadSet() throws {
        let operations = UninstallOperations(
            state: PublishedState(
                payloads: .partial,
                configurationReferencesPayloads: false,
                stagedPayloads: [.partial]
            )
        )

        try PAMUninstallTransactionCoordinator(operations: operations).run()

        XCTAssertEqual(
            operations.state,
            PublishedState(
                payloads: .absent,
                configurationReferencesPayloads: false
            )
        )
        XCTAssertTrue(operations.snapshots.allSatisfy(\.isSafe))
    }

    func testRepairAndRemovalPreserveReferencedBrokenStateUntilTheyCanMakeItSafe() throws {
        for payloads in [PayloadSet.absent, .partial] {
            let interruptedState = PublishedState(
                payloads: payloads,
                configurationReferencesPayloads: true,
                stagedPayloads: [.complete(1)],
                hasTemporaryConfiguration: true
            )

            let install = InstallOperations(state: interruptedState)
            try PAMInstallTransactionCoordinator(operations: install).run()
            XCTAssertEqual(install.snapshots[1].payloads, payloads)
            XCTAssertTrue(install.snapshots[1].configurationReferencesPayloads)
            XCTAssertEqual(install.state.payloads, .complete(2))
            XCTAssertTrue(install.state.configurationReferencesPayloads)
            XCTAssertFalse(install.state.hasManagedResidue)

            let uninstall = UninstallOperations(state: interruptedState)
            try PAMUninstallTransactionCoordinator(operations: uninstall).run()
            XCTAssertEqual(
                uninstall.state,
                PublishedState(
                    payloads: .absent,
                    configurationReferencesPayloads: false
                )
            )
        }
    }

    func testRecoveryIsIdempotentForPersistentInterruptedStates() throws {
        let states = [
            PublishedState(
                payloads: .complete(2),
                configurationReferencesPayloads: false,
                stagedPayloads: [.partial],
                hasTemporaryConfiguration: true
            ),
            PublishedState(
                payloads: .complete(2),
                configurationReferencesPayloads: true,
                stagedPayloads: [.complete(1)],
                hasTemporaryConfiguration: true
            ),
            PublishedState(
                payloads: .partial,
                configurationReferencesPayloads: true,
                stagedPayloads: [.complete(2)],
                hasTemporaryConfiguration: true
            ),
        ]

        for state in states {
            let operations = InstallOperations(state: state)
            try operations.recoverInterruptedMutation()
            let recoveredState = operations.state
            try operations.recoverInterruptedMutation()

            XCTAssertEqual(operations.state, recoveredState)
        }
    }

    func testRecoveryFailureStopsBeforeTheTransactionMutatesAnythingElse() {
        let state = PublishedState(
            payloads: .complete(2),
            configurationReferencesPayloads: false,
            stagedPayloads: [.partial],
            hasTemporaryConfiguration: true
        )
        let operations = InstallOperations(
            state: state,
            failure: .recoverInterruptedMutation
        )

        XCTAssertThrowsError(
            try PAMInstallTransactionCoordinator(operations: operations).run()
        )

        XCTAssertEqual(operations.calls, [.recoverInterruptedMutation])
        XCTAssertEqual(operations.state, state)
    }

    func testManagedArtifactNamesRequireAnExactRandomSuffix() {
        XCTAssertTrue(PAMInstallerArtifactName.isStagingDirectory(".WhoSudod.stage.aB39Z0"))
        XCTAssertTrue(PAMInstallerArtifactName.isTemporaryConfiguration(".sudo.whosudod.123abc"))
        XCTAssertTrue(PAMInstallerArtifactName.isTemporaryPayload(".pam_whosudod.so.ABC123"))
        XCTAssertTrue(
            PAMInstallerArtifactName.isTemporaryPayload(
                ".whosudod-pam-terminal-reader.abcDEF"
            )
        )

        for name in [
            ".WhoSudod.stage.",
            ".WhoSudod.stage.12345",
            ".WhoSudod.stage.1234567",
            ".WhoSudod.stage.12345-",
            ".WhoSudod.stage.12345é",
            ".WhoSudod.stage.ABC123/foreign",
            ".WhoSudod.staging.ABC123",
        ] {
            XCTAssertFalse(PAMInstallerArtifactName.isStagingDirectory(name))
        }
        XCTAssertFalse(
            PAMInstallerArtifactName.isTemporaryConfiguration(
                ".sudo.whosudod.ABC123.backup"
            )
        )
        XCTAssertFalse(
            PAMInstallerArtifactName.isTemporaryPayload(
                ".pam_whosudod.so.ABC123.backup"
            )
        )
    }
}

protocol PAMInstallTransactionOperations {
    associatedtype PayloadActivation

    /// Atomically publishes a complete payload set. If this throws, the
    /// previously active payload set must remain active.
    func activateCompletePayloadSet() throws -> PayloadActivation

    func validateActivatedPayloadSet() throws
    func persistActivatedPayloadSet() throws
    func validateConfigurationBeforeCommit() throws

    /// Atomically publishes the PAM configuration. This method must not throw
    /// after the configuration rename commits references to the new payloads.
    func commitConfigurationReferencingPayloads() throws

    /// Best-effort cleanup after the configuration commit point. The active
    /// payload set and configuration must remain valid if cleanup is incomplete.
    func discardPreviousPayloadSet(after activation: PayloadActivation)

    /// Recovers from a failure before the configuration commit. The operation
    /// can restore the previous set or keep the new complete set, but existing
    /// configuration references must never point to an incomplete payload set.
    /// It must not delete the previous set before activation persistence is
    /// confirmed, because a restart can restore the old directory mapping.
    func recoverFromPrecommitFailure(
        after activation: PayloadActivation,
        activationWasPersisted: Bool
    )
}

struct PAMInstallTransactionCoordinator<Operations: PAMInstallTransactionOperations> {
    let operations: Operations

    func run() throws {
        let activation = try operations.activateCompletePayloadSet()
        var configurationCommitted = false
        var activationWasPersisted = false
        defer {
            if !configurationCommitted {
                operations.recoverFromPrecommitFailure(
                    after: activation,
                    activationWasPersisted: activationWasPersisted
                )
            }
        }

        try operations.validateActivatedPayloadSet()
        try operations.persistActivatedPayloadSet()
        activationWasPersisted = true
        try operations.validateConfigurationBeforeCommit()
        try operations.commitConfigurationReferencingPayloads()

        // The configuration rename is the install commit point. From here,
        // rollback could make PAM reference a payload set that is not active.
        configurationCommitted = true
        operations.discardPreviousPayloadSet(after: activation)
    }
}

protocol PAMUninstallTransactionOperations {
    /// Atomically publishes a PAM configuration without Who Sudo'd references.
    /// This method must not throw after that rename commits.
    func commitConfigurationWithoutPayloadReferences() throws

    func persistConfigurationWithoutPayloadReferences() throws

    /// Re-reads the active configuration and verifies that it still has no
    /// payload references immediately before payload removal.
    func validatePayloadRemoval() throws
    func removePayloadSet() throws
}

struct PAMUninstallTransactionCoordinator<Operations: PAMUninstallTransactionOperations> {
    let operations: Operations

    func run() throws {
        try operations.commitConfigurationWithoutPayloadReferences()
        try operations.persistConfigurationWithoutPayloadReferences()
        try operations.validatePayloadRemoval()
        try operations.removePayloadSet()
    }
}

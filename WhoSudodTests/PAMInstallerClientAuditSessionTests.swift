import XCTest

final class PAMInstallerClientAuditSessionTests: XCTestCase {
    private let client = PAMInstallerClientAuditSession(
        userIdentifier: 501,
        sessionIdentifier: 41
    )

    private func auditSession(
        userIdentifier: uid_t,
        sessionIdentifier: au_asid_t
    ) -> auditinfo_addr {
        var session = auditinfo_addr()
        session.ai_auid = userIdentifier
        session.ai_asid = sessionIdentifier
        return session
    }

    func testAdopterRejectsRootClientBeforeReadingAuditState() {
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                XCTFail("The adopter must reject the client before resolving it.")
                return self.auditSession(userIdentifier: 0, sessionIdentifier: 41)
            },
            readCurrentSession: {
                XCTFail("The adopter must reject the client before reading its state.")
                return self.auditSession(userIdentifier: 0, sessionIdentifier: 0)
            },
            setSession: { _ in
                XCTFail("The adopter must reject the client before setting its state.")
            }
        )

        XCTAssertThrowsError(
            try adopter.adopt(
                PAMInstallerClientAuditSession(
                    userIdentifier: 0,
                    sessionIdentifier: 41
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .invalidUser
            )
        }
    }

    func testAdopterRejectsNonpositiveClientSessionsBeforeReadingAuditState() {
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                XCTFail("The adopter must reject the client before resolving it.")
                return self.auditSession(userIdentifier: 501, sessionIdentifier: 41)
            },
            readCurrentSession: {
                XCTFail("The adopter must reject the client before reading its state.")
                return self.auditSession(userIdentifier: 0, sessionIdentifier: 0)
            },
            setSession: { _ in
                XCTFail("The adopter must reject the client before setting its state.")
            }
        )

        for sessionIdentifier: au_asid_t in [0, -1] {
            XCTAssertThrowsError(
                try adopter.adopt(
                    PAMInstallerClientAuditSession(
                        userIdentifier: 501,
                        sessionIdentifier: sessionIdentifier
                    )
                )
            ) { error in
                XCTAssertEqual(
                    error as? PAMInstallerClientAuditSessionError,
                    .invalidSession
                )
            }
        }
    }

    func testAdopterRejectsAResolvedSessionIdentifierMismatch() {
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                self.auditSession(userIdentifier: 501, sessionIdentifier: 42)
            },
            readCurrentSession: {
                XCTFail("The adopter must verify the resolved session first.")
                return self.auditSession(userIdentifier: 0, sessionIdentifier: 0)
            },
            setSession: { _ in
                XCTFail("The adopter must verify the resolved session first.")
            }
        )

        XCTAssertThrowsError(try adopter.adopt(client)) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .sessionMismatch
            )
        }
    }

    func testAdopterRejectsAResolvedUserMismatch() {
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                self.auditSession(userIdentifier: 502, sessionIdentifier: 41)
            },
            readCurrentSession: {
                XCTFail("The adopter must verify the resolved user first.")
                return self.auditSession(userIdentifier: 0, sessionIdentifier: 0)
            },
            setSession: { _ in
                XCTFail("The adopter must verify the resolved user first.")
            }
        )

        XCTAssertThrowsError(try adopter.adopt(client)) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .userMismatch
            )
        }
    }

    func testAdopterDoesNotSetAnAlreadyMatchingSession() throws {
        var readCount = 0
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                self.auditSession(userIdentifier: 501, sessionIdentifier: 41)
            },
            readCurrentSession: {
                readCount += 1
                return self.auditSession(userIdentifier: 501, sessionIdentifier: 41)
            },
            setSession: { _ in
                XCTFail("The adopter must not set an already matching session.")
            }
        )

        try adopter.adopt(client)

        XCTAssertEqual(readCount, 1)
    }

    func testAdopterRejectsAnExistingDifferentHelperSession() {
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                self.auditSession(userIdentifier: 501, sessionIdentifier: 41)
            },
            readCurrentSession: {
                self.auditSession(userIdentifier: 502, sessionIdentifier: 42)
            },
            setSession: { _ in
                XCTFail("The adopter must not replace a different helper session.")
            }
        )

        XCTAssertThrowsError(try adopter.adopt(client)) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .differentSession
            )
        }
    }

    func testAdopterJoinsFromUnassignedNumberedHelperSessionAndVerifiesIt() throws {
        var calls: [String] = []
        var currentSession = auditSession(
            userIdentifier: uid_t.max,
            sessionIdentifier: 100016
        )
        let targetSession = auditSession(userIdentifier: 501, sessionIdentifier: 41)
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { identifier in
                calls.append("resolve:\(identifier)")
                return targetSession
            },
            readCurrentSession: {
                calls.append("read")
                return currentSession
            },
            setSession: { session in
                calls.append("set")
                currentSession = session
            }
        )

        try adopter.adopt(client)

        XCTAssertEqual(calls, ["resolve:41", "read", "set", "read"])
        XCTAssertEqual(currentSession.ai_auid, 501)
        XCTAssertEqual(currentSession.ai_asid, 41)
    }

    func testAdopterRejectsFailedReadBackWithoutTryingToRestore() {
        var readCount = 0
        var setCount = 0
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                self.auditSession(userIdentifier: 501, sessionIdentifier: 41)
            },
            readCurrentSession: {
                readCount += 1
                return self.auditSession(
                    userIdentifier: uid_t.max,
                    sessionIdentifier: 100016
                )
            },
            setSession: { _ in setCount += 1 }
        )

        XCTAssertThrowsError(try adopter.adopt(client)) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .verificationFailed
            )
        }
        XCTAssertEqual(readCount, 2)
        XCTAssertEqual(setCount, 1)
    }

    func testAdopterRejectsAssignedUserEvenWithDefaultSessionIdentifier() {
        let adopter = SystemPAMInstallerClientAuditSessionAdopter(
            resolveSession: { _ in
                self.auditSession(userIdentifier: 501, sessionIdentifier: 41)
            },
            readCurrentSession: {
                self.auditSession(userIdentifier: 502, sessionIdentifier: 0)
            },
            setSession: { _ in
                XCTFail("An assigned user must not be replaced.")
            }
        )

        XCTAssertThrowsError(try adopter.adopt(client)) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .differentSession
            )
        }
    }

    func testFirstOperationAdoptsClientSession() throws {
        let client = PAMInstallerClientAuditSession(
            userIdentifier: 501,
            sessionIdentifier: 41
        )
        var adopted: [PAMInstallerClientAuditSession] = []
        var operationRan = false
        let gate = PAMInstallerClientAuditSessionGate { adopted.append($0) }

        try gate.perform(client: client) {
            operationRan = true
        }

        XCTAssertEqual(adopted, [client])
        XCTAssertTrue(operationRan)
    }

    func testSameClientSessionCanRunMoreThanOneOperation() throws {
        let client = PAMInstallerClientAuditSession(
            userIdentifier: 501,
            sessionIdentifier: 41
        )
        var adoptionCount = 0
        var operationCount = 0
        let gate = PAMInstallerClientAuditSessionGate { _ in adoptionCount += 1 }

        for _ in 0..<2 {
            try gate.perform(client: client) {
                operationCount += 1
            }
        }

        XCTAssertEqual(adoptionCount, 1)
        XCTAssertEqual(operationCount, 2)
    }

    func testDifferentClientSessionIsRejectedBeforeOperation() throws {
        let firstClient = PAMInstallerClientAuditSession(
            userIdentifier: 501,
            sessionIdentifier: 41
        )
        let secondClient = PAMInstallerClientAuditSession(
            userIdentifier: 502,
            sessionIdentifier: 42
        )
        var operationRan = false
        let gate = PAMInstallerClientAuditSessionGate { _ in }
        try gate.perform(client: firstClient) {}

        XCTAssertThrowsError(
            try gate.perform(client: secondClient) {
                operationRan = true
            }
        ) { error in
            XCTAssertEqual(
                error as? PAMInstallerClientAuditSessionError,
                .differentSession
            )
        }
        XCTAssertFalse(operationRan)
    }

    func testAdoptionFailureStopsOperationAndCanBeRetried() throws {
        let client = PAMInstallerClientAuditSession(
            userIdentifier: 501,
            sessionIdentifier: 41
        )
        var adoptionCount = 0
        var operationCount = 0
        let gate = PAMInstallerClientAuditSessionGate { _ in
            adoptionCount += 1
            if adoptionCount == 1 {
                throw PAMInstallerClientAuditSessionError.verificationFailed
            }
        }

        XCTAssertThrowsError(
            try gate.perform(client: client) {
                operationCount += 1
            }
        )
        try gate.perform(client: client) {
            operationCount += 1
        }
        try gate.perform(client: client) {
            operationCount += 1
        }

        XCTAssertEqual(adoptionCount, 2)
        XCTAssertEqual(operationCount, 2)
    }
}

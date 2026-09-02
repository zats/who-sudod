import XCTest
@testable import WhoSudod

final class PAMConversationProtocolTests: XCTestCase {
    func testOnlyExactOpenPAMPasswordPromptsAreEligible() {
        XCTAssertTrue(PAMPromptPolicy.isAccountPasswordPrompt("Password:"))
        XCTAssertTrue(PAMPromptPolicy.isAccountPasswordPrompt("Password: "))

        for prompt in [
            " Password:",
            "Password:\t",
            "zats's Password:",
            "PIN:",
            "YubiKey PIN:",
            "Verification code:",
            "Password and OTP:",
            "Username:"
        ] {
            XCTAssertFalse(
                PAMPromptPolicy.isAccountPasswordPrompt(prompt),
                "Unexpectedly accepted prompt: \(prompt)"
            )
        }
    }

    func testParsesBoundedBeginFrame() throws {
        let identifier = try XCTUnwrap(
            PAMRequestIdentifier(bytes: Data(0..<16))
        )
        let username = Data("zats".utf8)
        let terminal = Data("/dev/ttys001".utf8)
        let prompt = Data("Password:".utf8)
        var payload = Data()
        append(UInt32(4_242), to: &payload)
        append(UInt32(501), to: &payload)
        append(UInt16(username.count), to: &payload)
        append(UInt16(terminal.count), to: &payload)
        append(UInt16(prompt.count), to: &payload)
        append(UInt16(0), to: &payload)
        payload.append(username)
        payload.append(terminal)
        payload.append(prompt)

        let frame = try XCTUnwrap(
            PAMConversationWire.frame(
                type: .begin,
                requestIdentifier: identifier,
                payload: payload
            )
        )
        let header = try XCTUnwrap(
            PAMConversationWire.parseHeader(
                frame.prefix(PAMConversationWire.headerLength)
            )
        )
        let request = try XCTUnwrap(
            PAMConversationWire.parseBegin(
                header: header,
                payload: frame.dropFirst(PAMConversationWire.headerLength)
            )
        )

        XCTAssertEqual(request.identifier, identifier)
        XCTAssertEqual(request.processID, 4_242)
        XCTAssertEqual(request.realUserID, 501)
        XCTAssertEqual(request.username, "zats")
        XCTAssertEqual(request.terminal, "/dev/ttys001")
        XCTAssertEqual(request.prompt, "Password:")
    }

    func testRejectsMalformedBeginPayloadAndOversizedPassword() throws {
        let identifier = try XCTUnwrap(
            PAMRequestIdentifier(bytes: Data(repeating: 0x41, count: 16))
        )
        var payload = Data(repeating: 0, count: 16)
        payload[3] = 42
        payload[9] = 10

        let header = PAMConversationWire.Header(
            type: .begin,
            payloadLength: payload.count,
            requestIdentifier: identifier
        )
        XCTAssertNil(PAMConversationWire.parseBegin(header: header, payload: payload))
        XCTAssertNil(
            PAMConversationWire.frame(
                type: .password,
                requestIdentifier: identifier,
                payload: Data(
                    repeating: 0x41,
                    count: PAMConversationWire.maximumPayloadLength + 1
                )
            )
        )
    }

    func testRejectsProcessIdentifierOutsidePIDRange() throws {
        let identifier = try XCTUnwrap(
            PAMRequestIdentifier(bytes: Data(repeating: 0x41, count: 16))
        )
        var payload = Data()
        append(UInt32.max, to: &payload)
        append(UInt32(501), to: &payload)
        append(UInt16(0), to: &payload)
        append(UInt16(0), to: &payload)
        append(UInt16(0), to: &payload)
        append(UInt16(0), to: &payload)
        let header = PAMConversationWire.Header(
            type: .begin,
            payloadLength: payload.count,
            requestIdentifier: identifier
        )

        XCTAssertNil(PAMConversationWire.parseBegin(header: header, payload: payload))
    }

    func testRejectsHeaderWithUnknownTypeOrOversizedPayload() throws {
        let identifier = try XCTUnwrap(
            PAMRequestIdentifier(bytes: Data(repeating: 0x42, count: 16))
        )
        var unknownType = try XCTUnwrap(
            PAMConversationWire.frame(type: .begin, requestIdentifier: identifier)
        )
        unknownType[6] = 0xff
        unknownType[7] = 0xff
        XCTAssertNil(PAMConversationWire.parseHeader(unknownType))

        var oversized = unknownType
        oversized[6] = 0
        oversized[7] = UInt8(PAMConversationWire.MessageType.begin.rawValue)
        let invalidLength = UInt32(PAMConversationWire.maximumPayloadLength + 1)
        oversized[8] = UInt8((invalidLength >> 24) & 0xff)
        oversized[9] = UInt8((invalidLength >> 16) & 0xff)
        oversized[10] = UInt8((invalidLength >> 8) & 0xff)
        oversized[11] = UInt8(invalidLength & 0xff)
        XCTAssertNil(PAMConversationWire.parseHeader(oversized))
    }

    func testConversationLeaseCanOnlyBecomeInactive() {
        let lease = PAMConversationLease()
        XCTAssertTrue(lease.isActive)
        lease.invalidate()
        XCTAssertFalse(lease.isActive)
        lease.invalidate()
        XCTAssertFalse(lease.isActive)
    }

    func testReadyFrameIsEmptyAndUsesRequestIdentifier() throws {
        let identifier = try XCTUnwrap(
            PAMRequestIdentifier(bytes: Data(repeating: 0x42, count: 16))
        )
        let frame = try XCTUnwrap(
            PAMConversationWire.frame(
                type: .ready,
                requestIdentifier: identifier
            )
        )
        let header = try XCTUnwrap(PAMConversationWire.parseHeader(frame))

        XCTAssertEqual(header.type, .ready)
        XCTAssertEqual(header.payloadLength, 0)
        XCTAssertEqual(header.requestIdentifier, identifier)
    }

    private func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }
}

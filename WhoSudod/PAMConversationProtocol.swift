import Darwin
import Foundation

struct PAMRequestIdentifier: Hashable, Sendable {
    static let byteCount = 16

    let bytes: Data

    init?(bytes: Data) {
        guard bytes.count == Self.byteCount else {
            return nil
        }
        self.bytes = bytes
    }

    var uuid: UUID {
        let value = [UInt8](bytes)
        return UUID(
            uuid: (
                value[0], value[1], value[2], value[3],
                value[4], value[5], value[6], value[7],
                value[8], value[9], value[10], value[11],
                value[12], value[13], value[14], value[15]
            )
        )
    }
}

struct PAMPasswordRequest: Equatable, Sendable {
    let identifier: PAMRequestIdentifier
    let processID: pid_t
    let realUserID: uid_t
    let username: String
    let terminal: String
    let prompt: String
}

enum PAMPromptPolicy {
    static func isAccountPasswordPrompt(_ prompt: String) -> Bool {
        prompt == "Password:" || prompt == "Password: "
    }
}

enum PAMConversationWire {
    static let magic: UInt32 = 0x5753_504d
    static let version: UInt16 = 1
    static let headerLength = 28
    static let maximumPayloadLength = 4_096
    static let maximumUsernameLength = 256
    static let maximumTerminalLength = 256
    static let maximumPromptLength = 1_024
    static let maximumPasswordLength = 511

    enum MessageType: UInt16 {
        case begin = 1
        case password = 2
        case cancel = 3
        case end = 4
        case ready = 5
    }

    struct Header: Equatable, Sendable {
        let type: MessageType
        let payloadLength: Int
        let requestIdentifier: PAMRequestIdentifier
    }

    static func parseHeader(_ data: Data) -> Header? {
        let data = Data(data)
        guard data.count == headerLength,
              readUInt32(data, at: 0) == magic,
              readUInt16(data, at: 4) == version,
              let rawType = readUInt16(data, at: 6),
              let type = MessageType(rawValue: rawType),
              let rawLength = readUInt32(data, at: 8),
              rawLength <= maximumPayloadLength,
              let requestIdentifier = PAMRequestIdentifier(
                  bytes: data.subdata(in: 12..<28)
              ) else {
            return nil
        }
        return Header(
            type: type,
            payloadLength: Int(rawLength),
            requestIdentifier: requestIdentifier
        )
    }

    static func parseBegin(
        header: Header,
        payload: Data
    ) -> PAMPasswordRequest? {
        let payload = Data(payload)
        guard header.type == .begin,
              payload.count == header.payloadLength,
              payload.count >= 16,
              let rawProcessID = readUInt32(payload, at: 0),
              let rawUserID = readUInt32(payload, at: 4),
              let usernameLength = readUInt16(payload, at: 8).map(Int.init),
              let terminalLength = readUInt16(payload, at: 10).map(Int.init),
              let promptLength = readUInt16(payload, at: 12).map(Int.init),
              readUInt16(payload, at: 14) == 0,
              usernameLength <= maximumUsernameLength,
              terminalLength <= maximumTerminalLength,
              promptLength <= maximumPromptLength,
              16 + usernameLength + terminalLength + promptLength == payload.count,
              rawProcessID > 1,
              rawProcessID <= UInt32(Int32.max) else {
            return nil
        }

        let usernameStart = 16
        let terminalStart = usernameStart + usernameLength
        let promptStart = terminalStart + terminalLength
        guard let username = strictUTF8(
                  payload.subdata(in: usernameStart..<terminalStart)
              ),
              let terminal = strictUTF8(
                  payload.subdata(in: terminalStart..<promptStart)
              ),
              let prompt = strictUTF8(
                  payload.subdata(in: promptStart..<payload.count)
              ),
              !username.contains("\0"),
              !terminal.contains("\0"),
              !prompt.contains("\0") else {
            return nil
        }

        return PAMPasswordRequest(
            identifier: header.requestIdentifier,
            processID: pid_t(bitPattern: rawProcessID),
            realUserID: uid_t(rawUserID),
            username: username,
            terminal: terminal,
            prompt: prompt
        )
    }

    static func frame(
        type: MessageType,
        requestIdentifier: PAMRequestIdentifier,
        payload: Data = Data()
    ) -> Data? {
        guard payload.count <= maximumPayloadLength else {
            return nil
        }
        var data = Data(capacity: headerLength + payload.count)
        append(magic, to: &data)
        append(version, to: &data)
        append(type.rawValue, to: &data)
        append(UInt32(payload.count), to: &data)
        data.append(requestIdentifier.bytes)
        data.append(payload)
        return data
    }

    private static func strictUTF8(_ data: Data) -> String? {
        String(data: data, encoding: .utf8)
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= data.count else {
            return nil
        }
        return data.withUnsafeBytes { bytes in
            let base = bytes.bindMemory(to: UInt8.self)
            return (UInt16(base[offset]) << 8) | UInt16(base[offset + 1])
        }
    }

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else {
            return nil
        }
        return data.withUnsafeBytes { bytes in
            let base = bytes.bindMemory(to: UInt8.self)
            return (UInt32(base[offset]) << 24)
                | (UInt32(base[offset + 1]) << 16)
                | (UInt32(base[offset + 2]) << 8)
                | UInt32(base[offset + 3])
        }
    }

    private static func append(_ value: UInt16, to data: inout Data) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    private static func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }
}

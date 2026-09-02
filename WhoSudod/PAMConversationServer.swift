import Darwin
import Foundation
import os

enum PAMConversationServerError: LocalizedError {
    case alreadyRunning
    case invalidExistingSocketPath
    case couldNotCreateSocket(Int32)
    case couldNotBindSocket(Int32)
    case couldNotSecureSocket(Int32)
    case couldNotListen(Int32)

    var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            "Another Who Sudo'd process already owns the PAM communication socket."
        case .invalidExistingSocketPath:
            "The PAM communication socket path is not safe to replace."
        case let .couldNotCreateSocket(code):
            "Could not create the PAM communication socket (errno \(code))."
        case let .couldNotBindSocket(code):
            "Could not bind the PAM communication socket (errno \(code))."
        case let .couldNotSecureSocket(code):
            "Could not secure the PAM communication socket (errno \(code))."
        case let .couldNotListen(code):
            "Could not listen on the PAM communication socket (errno \(code))."
        }
    }
}

final class PAMConversationLease: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true

    var isActive: Bool {
        lock.withLock { active }
    }

    func invalidate() {
        lock.withLock {
            active = false
        }
    }
}

final class PAMConversationServer: @unchecked Sendable {
    typealias RequestHandler = @MainActor (
        PAMPasswordRequest,
        PAMConversationLease
    ) async -> Bool
    typealias EndHandler = @MainActor (PAMRequestIdentifier) -> Void

    static func socketPath(userID: uid_t = getuid()) -> String {
        "/private/tmp/com.zats.WhoSudo.pam.\(userID).sock"
    }

    private final class Connection: @unchecked Sendable {
        let descriptor: Int32
        let requestIdentifier: PAMRequestIdentifier
        let lease = PAMConversationLease()
        private let closeLock = NSLock()
        private var isClosed = false

        init(descriptor: Int32, requestIdentifier: PAMRequestIdentifier) {
            self.descriptor = descriptor
            self.requestIdentifier = requestIdentifier
        }

        func close() {
            lease.invalidate()
            closeLock.lock()
            defer { closeLock.unlock() }
            guard !isClosed else {
                return
            }
            isClosed = true
            shutdown(descriptor, SHUT_RDWR)
            Darwin.close(descriptor)
        }
    }

    private let logger = Logger(subsystem: "com.zats.WhoSudo", category: "PAMConversation")
    private let socketPath: String
    private let requestHandler: RequestHandler
    private let endHandler: EndHandler
    private let stateQueue = DispatchQueue(label: "com.zats.WhoSudo.pam-conversation.state")
    private let connectionQueue = DispatchQueue(
        label: "com.zats.WhoSudo.pam-conversation.connections",
        attributes: .concurrent
    )
    private var listenerDescriptor: Int32 = -1
    private var listenerSource: DispatchSourceRead?
    private var listenerGeneration: UInt64 = 0
    private var boundSocketIdentity: SocketIdentity?
    private var connections: [PAMRequestIdentifier: Connection] = [:]

    private struct SocketIdentity: Equatable {
        let device: dev_t
        let inode: ino_t

        init(_ status: stat) {
            device = status.st_dev
            inode = status.st_ino
        }
    }

    init(
        socketPath: String = PAMConversationServer.socketPath(),
        requestHandler: @escaping RequestHandler,
        endHandler: @escaping EndHandler
    ) {
        self.socketPath = socketPath
        self.requestHandler = requestHandler
        self.endHandler = endHandler
    }

    deinit {
        stop()
    }

    func start() throws {
        try stateQueue.sync {
            guard listenerDescriptor < 0 else {
                return
            }
            let path = socketPath
            try removeStaleSocketIfSafe(at: path)

            let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
            guard descriptor >= 0 else {
                throw PAMConversationServerError.couldNotCreateSocket(errno)
            }
            var createdSocketIdentity: SocketIdentity?
            do {
                guard fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
                    throw PAMConversationServerError.couldNotCreateSocket(errno)
                }
                try bind(descriptor: descriptor, path: path)
                createdSocketIdentity = try socketIdentity(at: path)
                guard chmod(path, S_IRUSR | S_IWUSR) == 0 else {
                    throw PAMConversationServerError.couldNotSecureSocket(errno)
                }
                guard listen(descriptor, 8) == 0 else {
                    throw PAMConversationServerError.couldNotListen(errno)
                }
            } catch {
                Darwin.close(descriptor)
                if let createdSocketIdentity {
                    unlinkSocket(at: path, ifIdentityMatches: createdSocketIdentity)
                }
                throw error
            }

            listenerDescriptor = descriptor
            boundSocketIdentity = createdSocketIdentity
            listenerGeneration &+= 1
            let source = DispatchSource.makeReadSource(
                fileDescriptor: descriptor,
                queue: stateQueue
            )
            source.setEventHandler { [weak self] in
                self?.acceptConnections()
            }
            source.setCancelHandler {
                Darwin.close(descriptor)
            }
            listenerSource = source
            source.activate()
        }
    }

    func stop() {
        stateQueue.sync {
            listenerGeneration &+= 1
            let activeConnections = Array(connections.values)
            connections.removeAll()
            for connection in activeConnections {
                connection.close()
            }
            listenerSource?.cancel()
            listenerSource = nil
            listenerDescriptor = -1

            if let boundSocketIdentity {
                unlinkSocket(
                    at: socketPath,
                    ifIdentityMatches: boundSocketIdentity
                )
            }
            boundSocketIdentity = nil
        }
    }

    func submit(password: Data, for requestIdentifier: PAMRequestIdentifier) {
        guard !password.isEmpty,
              password.count <= PAMConversationWire.maximumPasswordLength else {
            return
        }
        send(type: .password, payload: password, for: requestIdentifier)
    }

    func useTerminal(for requestIdentifier: PAMRequestIdentifier) {
        send(type: .cancel, payload: Data(), for: requestIdentifier)
    }

    private func send(
        type: PAMConversationWire.MessageType,
        payload: Data,
        for requestIdentifier: PAMRequestIdentifier,
        expectedConnection: Connection? = nil
    ) {
        stateQueue.async { [weak self] in
            guard let self,
                  let connection = self.connections[requestIdentifier],
                  expectedConnection == nil || connection === expectedConnection,
                  var frame = PAMConversationWire.frame(
                      type: type,
                      requestIdentifier: requestIdentifier,
                      payload: payload
                  ) else {
                return
            }
            defer {
                frame.resetBytes(in: frame.startIndex..<frame.endIndex)
            }
            guard Self.writeAll(frame, to: connection.descriptor) else {
                self.finishConnection(connection, notifiesUI: true)
                return
            }
        }
    }

    private func acceptConnections() {
        let acceptedGeneration = listenerGeneration
        while true {
            let descriptor = accept(listenerDescriptor, nil, nil)
            if descriptor < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                    return
                }
                return
            }
            let currentFlags = fcntl(descriptor, F_GETFL)
            if currentFlags < 0
                || fcntl(descriptor, F_SETFL, currentFlags & ~O_NONBLOCK) != 0 {
                Darwin.close(descriptor)
                continue
            }
            connectionQueue.async { [weak self] in
                self?.receiveConnection(
                    descriptor,
                    listenerGeneration: acceptedGeneration
                )
            }
        }
    }

    private func receiveConnection(
        _ descriptor: Int32,
        listenerGeneration acceptedGeneration: UInt64
    ) {
        guard let peer = validatedPeer(for: descriptor),
              let headerData = Self.readExactly(
                  count: PAMConversationWire.headerLength,
                  from: descriptor
              ),
              let header = PAMConversationWire.parseHeader(headerData),
              header.type == .begin,
              let payload = Self.readExactly(
                  count: header.payloadLength,
                  from: descriptor
              ),
              let request = PAMConversationWire.parseBegin(
                  header: header,
                  payload: payload
              ),
              request.processID == peer.processID,
              request.realUserID == getuid(),
              PAMPromptPolicy.isAccountPasswordPrompt(request.prompt) else {
            Darwin.close(descriptor)
            return
        }

        let connection = Connection(
            descriptor: descriptor,
            requestIdentifier: request.identifier
        )
        stateQueue.async { [weak self] in
            guard let self else {
                connection.close()
                return
            }
            guard self.listenerDescriptor >= 0,
                  self.listenerGeneration == acceptedGeneration,
                  self.connections[request.identifier] == nil else {
                connection.close()
                return
            }
            self.connections[request.identifier] = connection
            Task { @MainActor [weak self] in
                guard let self else {
                    return
                }
                let accepted = await self.requestHandler(request, connection.lease)
                if accepted {
                    self.send(
                        type: .ready,
                        payload: Data(),
                        for: request.identifier,
                        expectedConnection: connection
                    )
                } else {
                    self.send(
                        type: .cancel,
                        payload: Data(),
                        for: request.identifier,
                        expectedConnection: connection
                    )
                }
            }
        }

        guard let nextHeaderData = Self.readExactly(
                  count: PAMConversationWire.headerLength,
                  from: descriptor
              ),
              let nextHeader = PAMConversationWire.parseHeader(nextHeaderData),
              nextHeader.requestIdentifier == request.identifier,
              nextHeader.type == .end,
              nextHeader.payloadLength == 0 else {
            connection.lease.invalidate()
            stateQueue.async { [weak self] in
                self?.finishConnection(connection, notifiesUI: true)
            }
            return
        }
        connection.lease.invalidate()
        stateQueue.async { [weak self] in
            self?.finishConnection(connection, notifiesUI: true)
        }
    }

    private func finishConnection(_ connection: Connection, notifiesUI: Bool) {
        let activeConnection = connections[connection.requestIdentifier]
        let wasActive = activeConnection === connection
        if wasActive {
            connections.removeValue(forKey: connection.requestIdentifier)
        }
        connection.lease.invalidate()
        connection.close()
        guard wasActive, notifiesUI else {
            return
        }
        Task { @MainActor [endHandler] in
            endHandler(connection.requestIdentifier)
        }
    }

    private struct Peer {
        let processID: pid_t
    }

    private func validatedPeer(for descriptor: Int32) -> Peer? {
        var effectiveUserID: uid_t = 0
        var effectiveGroupID: gid_t = 0
        guard getpeereid(
            descriptor,
            &effectiveUserID,
            &effectiveGroupID
        ) == 0,
        effectiveUserID == 0 else {
            return nil
        }

        var processID: pid_t = 0
        var processIDLength = socklen_t(MemoryLayout.size(ofValue: processID))
        guard getsockopt(
            descriptor,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &processID,
            &processIDLength
        ) == 0,
        processID > 1 else {
            return nil
        }

        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let pathLength = proc_pidpath(
            processID,
            &pathBuffer,
            UInt32(pathBuffer.count)
        )
        let path = String(
            decoding: pathBuffer.prefix(Int(max(0, pathLength))).map {
                UInt8(bitPattern: $0)
            },
            as: UTF8.self
        )
        guard pathLength > 0,
              path == "/usr/bin/sudo" else {
            return nil
        }
        return Peer(processID: processID)
    }

    private func removeStaleSocketIfSafe(at path: String) throws {
        var status = stat()
        guard lstat(path, &status) == 0 else {
            if errno == ENOENT {
                return
            }
            throw PAMConversationServerError.invalidExistingSocketPath
        }
        guard (status.st_mode & S_IFMT) == S_IFSOCK,
              status.st_uid == getuid() else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }
        let identity = SocketIdentity(status)
        switch try probeSocket(at: path) {
        case .live:
            throw PAMConversationServerError.alreadyRunning
        case .stale:
            break
        }
        var currentStatus = stat()
        guard lstat(path, &currentStatus) == 0,
              (currentStatus.st_mode & S_IFMT) == S_IFSOCK,
              currentStatus.st_uid == getuid(),
              SocketIdentity(currentStatus) == identity,
              unlink(path) == 0 else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }
    }

    private enum SocketProbeResult {
        case live
        case stale
    }

    private func probeSocket(at path: String) throws -> SocketProbeResult {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }
        defer { Darwin.close(descriptor) }
        guard fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }

        var address = try socketAddress(for: path)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        if result == 0 {
            return .live
        }
        if errno == ECONNREFUSED {
            return .stale
        }
        guard errno == EINPROGRESS else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }

        var pollItem = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
        let pollResult = poll(&pollItem, 1, 100)
        guard pollResult > 0 else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }
        var connectionError: Int32 = 0
        var connectionErrorSize = socklen_t(MemoryLayout.size(ofValue: connectionError))
        guard getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_ERROR,
            &connectionError,
            &connectionErrorSize
        ) == 0 else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }
        if connectionError == 0 {
            return .live
        }
        if connectionError == ECONNREFUSED {
            return .stale
        }
        throw PAMConversationServerError.invalidExistingSocketPath
    }

    private func socketIdentity(at path: String) throws -> SocketIdentity {
        var status = stat()
        guard lstat(path, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFSOCK,
              status.st_uid == getuid() else {
            throw PAMConversationServerError.invalidExistingSocketPath
        }
        return SocketIdentity(status)
    }

    private func unlinkSocket(
        at path: String,
        ifIdentityMatches expectedIdentity: SocketIdentity
    ) {
        var status = stat()
        guard lstat(path, &status) == 0,
              (status.st_mode & S_IFMT) == S_IFSOCK,
              status.st_uid == getuid(),
              SocketIdentity(status) == expectedIdentity else {
            return
        }
        _ = unlink(path)
    }

    private func bind(descriptor: Int32, path: String) throws {
        var address = try socketAddress(for: path)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        guard result == 0 else {
            throw PAMConversationServerError.couldNotBindSocket(errno)
        }
    }

    private func socketAddress(for path: String) throws -> sockaddr_un {
        let utf8 = Array(path.utf8)
        guard utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw PAMConversationServerError.couldNotBindSocket(ENAMETOOLONG)
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            destination.copyBytes(from: utf8)
        }
        return address
    }

    private static func readExactly(count: Int, from descriptor: Int32) -> Data? {
        guard count >= 0, count <= PAMConversationWire.maximumPayloadLength else {
            return nil
        }
        if count == 0 {
            return Data()
        }
        var data = Data(count: count)
        let didRead = data.withUnsafeMutableBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else {
                return false
            }
            var offset = 0
            while offset < count {
                let result = recv(
                    descriptor,
                    base.advanced(by: offset),
                    count - offset,
                    0
                )
                if result > 0 {
                    offset += result
                    continue
                }
                if result < 0, errno == EINTR {
                    continue
                }
                return false
            }
            return true
        }
        return didRead ? data : nil
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) -> Bool {
        data.withUnsafeBytes { bytes -> Bool in
            guard let base = bytes.baseAddress else {
                return data.isEmpty
            }
            var offset = 0
            while offset < data.count {
                let result = Darwin.send(
                    descriptor,
                    base.advanced(by: offset),
                    data.count - offset,
                    MSG_NOSIGNAL
                )
                if result > 0 {
                    offset += result
                    continue
                }
                if result < 0, errno == EINTR {
                    continue
                }
                return false
            }
            return true
        }
    }
}

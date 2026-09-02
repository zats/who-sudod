import Darwin
import Foundation
import XCTest
@testable import WhoSudod

final class PAMConversationServerTests: XCTestCase {
    func testSecondServerDoesNotReplaceLiveListener() throws {
        let path = temporarySocketPath()
        defer { unlink(path) }
        let first = makeServer(path: path)
        let second = makeServer(path: path)
        try first.start()
        defer { first.stop() }

        XCTAssertThrowsError(try second.start()) { error in
            guard case PAMConversationServerError.alreadyRunning = error else {
                return XCTFail("Expected an already-running error, got \(error)")
            }
        }
        XCTAssertTrue(isSocket(at: path))
    }

    func testServerReplacesOnlyAStaleOwnedSocket() throws {
        let path = temporarySocketPath()
        defer { unlink(path) }
        let staleDescriptor = try bindSocket(at: path)
        close(staleDescriptor)

        let server = makeServer(path: path)
        try server.start()
        XCTAssertTrue(isSocket(at: path))
        server.stop()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testStopDoesNotRemoveAReplacementSocket() throws {
        let path = temporarySocketPath()
        defer { unlink(path) }
        let server = makeServer(path: path)
        try server.start()
        XCTAssertEqual(unlink(path), 0)

        let replacementDescriptor = try bindSocket(at: path)
        defer { close(replacementDescriptor) }
        server.stop()

        XCTAssertTrue(isSocket(at: path))
    }

    private func makeServer(path: String) -> PAMConversationServer {
        PAMConversationServer(
            socketPath: path,
            requestHandler: { _, _ in false },
            endHandler: { _ in }
        )
    }

    private func temporarySocketPath() -> String {
        "/tmp/who-sudod-test-\(UUID().uuidString).sock"
    }

    private func bindSocket(at path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw POSIXError(.ENFILE)
        }
        do {
            let bytes = Array(path.utf8)
            var address = sockaddr_un()
            guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
                throw POSIXError(.ENAMETOOLONG)
            }
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of: &address.sun_path) { destination in
                destination.initializeMemory(as: UInt8.self, repeating: 0)
                destination.copyBytes(from: bytes)
            }
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
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }

    private func isSocket(at path: String) -> Bool {
        var metadata = stat()
        return lstat(path, &metadata) == 0
            && metadata.st_mode & S_IFMT == S_IFSOCK
    }
}

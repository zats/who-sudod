import Darwin
import Foundation
import XCTest
@testable import WhoSudod

final class PAMExtendedACLInspectorTests: XCTestCase {
    func testNoExtendedACLIsAcceptedForPathAndDescriptor() throws {
        try withTemporaryFile { path, descriptor in
            XCTAssertEqual(PAMExtendedACLInspector.inspect(path: path), .absent)
            XCTAssertEqual(
                PAMExtendedACLInspector.inspect(fileDescriptor: descriptor),
                .absent
            )
        }
    }

    func testRealExtendedACLIsRejectedForPathAndDescriptor() throws {
        try withTemporaryFile { path, descriptor in
            try addExtendedACL(to: path)

            XCTAssertEqual(PAMExtendedACLInspector.inspect(path: path), .present)
            XCTAssertEqual(
                PAMExtendedACLInspector.inspect(fileDescriptor: descriptor),
                .present
            )
        }
    }

    private func withTemporaryFile(
        _ body: (String, Int32) throws -> Void
    ) throws {
        var pathTemplate = Array(
            "/private/tmp/whosudod-swift-acl-test.XXXXXX".utf8CString
        )
        let descriptor = pathTemplate.withUnsafeMutableBufferPointer { buffer in
            mkstemp(buffer.baseAddress!)
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let path = String(cString: pathTemplate)
        defer {
            close(descriptor)
            unlink(path)
        }

        try body(path, descriptor)
    }

    private func addExtendedACL(to path: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = [
            "+a",
            "group:everyone allow read",
            path,
        ]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }
}

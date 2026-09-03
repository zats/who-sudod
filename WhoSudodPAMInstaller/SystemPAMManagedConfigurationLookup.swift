import Darwin
import Foundation

enum SystemPAMManagedConfigurationLookup {
    static func path(for serviceType: String) throws -> String? {
        var pathBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        errno = 0
        let returnedLength = serviceType.withCString { serviceTypePointer in
            mcf_service_path_for_service_type(
                serviceTypePointer,
                &pathBuffer,
                pathBuffer.count
            )
        }
        let errorNumber = errno

        if returnedLength == 0 {
            if errorNumber == ENOENT {
                return nil
            }
            throw PAMManagedConfigurationError.lookupFailed(errorNumber)
        }

        guard returnedLength < pathBuffer.count else {
            throw PAMManagedConfigurationError.invalidLookupResponse
        }
        let pathBytes = pathBuffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:))
        let path = String(decoding: pathBytes, as: UTF8.self)
        guard !path.isEmpty, path.hasPrefix("/") else {
            throw PAMManagedConfigurationError.invalidLookupResponse
        }
        return path
    }
}

extension PAMManagedConfigurationGuard {
    static var system: Self {
        Self(pathLookup: SystemPAMManagedConfigurationLookup.path(for:))
    }
}

import Foundation

struct IgnoredApplicationRule: Codable, Equatable, Hashable, Sendable {
    let bundleIdentifier: String?
    let applicationPath: String
    let displayName: String
    let requestKinds: Set<AuthenticationRequestKind>

    var identifier: String {
        if let bundleIdentifier, !bundleIdentifier.isEmpty {
            return "bundle:\(bundleIdentifier)"
        }
        return "path:\(applicationPath)"
    }

    func matches(bundleIdentifier: String?, applicationPath: String) -> Bool {
        if let storedBundleIdentifier = self.bundleIdentifier,
           let bundleIdentifier,
           storedBundleIdentifier == bundleIdentifier {
            return true
        }
        return self.applicationPath == applicationPath
    }
}

struct RequestingApplication: Equatable, Sendable {
    let bundleIdentifier: String?
    let applicationPath: String
    let displayName: String
}

enum RequestingApplicationResolver {
    static func application(for chain: ProcessChain) -> RequestingApplication? {
        for process in chain.processes.reversed() {
            guard let executablePath = process.executablePath,
                  let applicationURL = enclosingApplicationURL(
                    forExecutablePath: executablePath
                  ) else {
                continue
            }
            let bundle = Bundle(url: applicationURL)
            return RequestingApplication(
                bundleIdentifier: bundle?.bundleIdentifier,
                applicationPath: applicationURL.path,
                displayName: displayName(
                    bundle: bundle,
                    applicationURL: applicationURL,
                    fallback: process.name
                )
            )
        }
        return nil
    }

    static func application(at url: URL) -> RequestingApplication? {
        let applicationURL = url
            .resolvingSymlinksInPath()
            .standardizedFileURL
        guard applicationURL.pathExtension.lowercased() == "app",
              let bundle = Bundle(url: applicationURL),
              bundle.executableURL != nil else {
            return nil
        }
        return RequestingApplication(
            bundleIdentifier: bundle.bundleIdentifier,
            applicationPath: applicationURL.path,
            displayName: displayName(
                bundle: bundle,
                applicationURL: applicationURL,
                fallback: applicationURL.deletingPathExtension().lastPathComponent
            )
        )
    }

    private static func enclosingApplicationURL(
        forExecutablePath executablePath: String
    ) -> URL? {
        var candidate = URL(fileURLWithPath: executablePath)
        while candidate.path != "/" {
            if candidate.pathExtension.lowercased() == "app",
               Bundle(url: candidate) != nil {
                return candidate
                    .resolvingSymlinksInPath()
                    .standardizedFileURL
            }
            candidate.deleteLastPathComponent()
        }
        return nil
    }

    private static func displayName(
        bundle: Bundle?,
        applicationURL: URL,
        fallback: String
    ) -> String {
        (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? (applicationURL.deletingPathExtension().lastPathComponent.isEmpty
                ? fallback
                : applicationURL.deletingPathExtension().lastPathComponent)
    }
}

enum IgnoredApplicationsPolicy {
    static func isIgnored(
        _ chain: ProcessChain,
        by rules: [IgnoredApplicationRule]
    ) -> Bool {
        guard let application = RequestingApplicationResolver.application(for: chain) else {
            return false
        }
        return rules.contains { rule in
            rule.requestKinds.contains(chain.requestKind)
                && rule.matches(
                    bundleIdentifier: application.bundleIdentifier,
                    applicationPath: application.applicationPath
                )
        }
    }

    static func filtering(
        _ snapshot: AuthenticationProcessSnapshot,
        by rules: [IgnoredApplicationRule]
    ) -> AuthenticationProcessSnapshot {
        AuthenticationProcessSnapshot(
            candidates: snapshot.candidates.filter { !isIgnored($0, by: rules) },
            inspectionState: snapshot.inspectionState
        )
    }
}

@MainActor
final class IgnoredApplicationsStore {
    static let defaultsKey = "IgnoredApplicationRules"
    static let defaultApplicationURLs = [
        URL(
            fileURLWithPath: "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/PasswordManagerBrowserExtensionHelper.app",
            isDirectory: true
        )
    ]

    private let defaults: UserDefaults
    private let defaultsKey: String
    private(set) var rules: [IgnoredApplicationRule]

    init(
        defaults: UserDefaults = .standard,
        defaultsKey: String = IgnoredApplicationsStore.defaultsKey,
        defaultApplicationURLs: [URL] = IgnoredApplicationsStore.defaultApplicationURLs
    ) {
        self.defaults = defaults
        self.defaultsKey = defaultsKey
        var loadedRules = Self.load(defaults: defaults, defaultsKey: defaultsKey)
        for defaultRule in defaultApplicationURLs.compactMap({ url in
            Self.makeRule(
                applicationURL: url,
                requestKinds: Set(AuthenticationRequestKind.allCases)
            )
        }) where !loadedRules.contains(where: { $0.identifier == defaultRule.identifier }) {
            loadedRules.append(defaultRule)
        }
        rules = loadedRules.sorted {
            $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
        }
        save()
    }

    @discardableResult
    func addApplication(
        at url: URL,
        requestKinds: Set<AuthenticationRequestKind> = Set(AuthenticationRequestKind.allCases)
    ) -> IgnoredApplicationRule? {
        guard !requestKinds.isEmpty,
              let rule = Self.makeRule(
                applicationURL: url,
                requestKinds: requestKinds
              ) else {
            return nil
        }
        if let index = rules.firstIndex(where: { $0.identifier == rule.identifier }) {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
        sortAndSave()
        return rule
    }

    func removeRule(identifier: String) {
        rules.removeAll { $0.identifier == identifier }
        save()
    }

    func setRequestKinds(
        _ requestKinds: Set<AuthenticationRequestKind>,
        for identifier: String
    ) {
        guard !requestKinds.isEmpty,
              let index = rules.firstIndex(where: { $0.identifier == identifier }) else {
            return
        }
        let current = rules[index]
        rules[index] = IgnoredApplicationRule(
            bundleIdentifier: current.bundleIdentifier,
            applicationPath: current.applicationPath,
            displayName: current.displayName,
            requestKinds: requestKinds
        )
        sortAndSave()
    }

    private func sortAndSave() {
        rules.sort {
            $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
        }
        save()
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(rules) else {
            return
        }
        defaults.set(data, forKey: defaultsKey)
    }

    private static func load(
        defaults: UserDefaults,
        defaultsKey: String
    ) -> [IgnoredApplicationRule] {
        guard let data = defaults.data(forKey: defaultsKey),
              let decoded = try? JSONDecoder().decode(
                [IgnoredApplicationRule].self,
                from: data
              ) else {
            return []
        }

        var identifiers: Set<String> = []
        return decoded
            .filter { !$0.requestKinds.isEmpty }
            .filter { identifiers.insert($0.identifier).inserted }
            .sorted {
                $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
            }
    }

    private static func makeRule(
        applicationURL: URL,
        requestKinds: Set<AuthenticationRequestKind>
    ) -> IgnoredApplicationRule? {
        guard let application = RequestingApplicationResolver.application(at: applicationURL) else {
            return nil
        }
        return IgnoredApplicationRule(
            bundleIdentifier: application.bundleIdentifier,
            applicationPath: application.applicationPath,
            displayName: application.displayName,
            requestKinds: requestKinds
        )
    }
}

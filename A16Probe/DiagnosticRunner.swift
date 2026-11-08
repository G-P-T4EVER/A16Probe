import Foundation
import OSLog

struct DiagnosticResult: Sendable {
    let text: String
    let file: URL
}

struct DiagnosticRunner {
    private static let logger = Logger(subsystem: "org.a16probe.research", category: "diagnostics")

    static func run() throws -> DiagnosticResult {
        let runID = UUID().uuidString
        let started = Date()
        let clock = ProcessInfo.processInfo.systemUptime
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var events: [[String: Any]] = []
        func event(_ phase: String, _ message: String) {
            events.append(["time": formatter.string(from: Date()),
                           "elapsedSeconds": ProcessInfo.processInfo.systemUptime - clock,
                           "phase": phase, "message": message])
            logger.info("\(phase, privacy: .public): \(message, privacy: .public)")
        }
        event("start", "Observation-only diagnostics started.")
        let snapshot = ContainerProbe.snapshot()
        event("runtime", "Read hardware and OS build; inspected already-loaded symbols without invoking them.")
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let assessment = Compatibility.assessment(
            machine: snapshot["hardwareIdentifier"] as? String ?? "unavailable",
            major: os.majorVersion, minor: os.minorVersion, patch: os.patchVersion,
            simulator: snapshot["simulator"] as? Bool ?? true)
        event("compatibility", "Compared model and numeric OS version; beta designation and vulnerability remain unverified.")
        let fm = FileManager.default
        let documents = try fm.url(for: .documentDirectory, in: .userDomainMask,
                                   appropriateFor: nil, create: true)
        var directory = documents.appendingPathComponent("A16ProbeReports", isDirectory: true)
        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try directory.setResourceValues(values)
        let file = directory.appendingPathComponent("A16Probe-\(runID).json")
        // Rotation touches only our own reports. Keep at most 19 before writing the next one.
        let existing = try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.creationDateKey, .isRegularFileKey, .isSymbolicLinkKey])
            .filter { $0.lastPathComponent.hasPrefix("A16Probe-") && $0.pathExtension == "json" }
            .filter {
                let resource = try $0.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                return resource.isRegularFile == true && resource.isSymbolicLink != true
            }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        let oldestFirst = try existing.map { ($0, try $0.resourceValues(forKeys: [.creationDateKey]).creationDate ?? .distantPast) }
            .sorted { $0.1 < $1.1 }
        for (old, _) in oldestFirst.prefix(max(0, oldestFirst.count - 19)) {
            try fm.removeItem(at: old)
        }
        event("storage", "Prepared app-owned report directory; retention limited to 20 reports, excluded from backup.")
        event("complete", "Observation completed. JSON persistence is confirmed by the UI only after writing succeeds.")
        let bundle = Bundle.main
        let report: [String: Any] = [
            "schemaVersion": 1, "runID": runID,
            "startedAt": formatter.string(from: started),
            "finishedAt": formatter.string(from: Date()),
            "application": ["version": bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown",
                            "build": bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"],
            "osVersion": "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            "runtime": snapshot, "compatibility": assessment, "events": events,
            "reference": ["repository": "https://github.com/forcequitOS/worse_query",
                          "commit": "d1540e20cd82b974d891e0551ced6d6aeb570ac2"],
            "scope": ["systemFilesModified": false, "foreignContainersEnumerated": false,
                      "newPrivateLibrariesLoaded": false, "networkRequests": false,
                      "writes": "Only this application's A16ProbeReports directory",
                      "deviceTestConclusion": "No exploit attempted; no exploit success claim"]
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        logger.info("Report saved in application sandbox.")
        return DiagnosticResult(text: String(decoding: data, as: UTF8.self), file: file)
    }
}

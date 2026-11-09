import Foundation
import OSLog
import Darwin

struct DiagnosticResult: Sendable {
    let text: String
    let file: URL
}

struct DiagnosticRunner {
    private static let logger = Logger(subsystem: "org.a16probe.research", category: "diagnostics")

    static func run(exploitTrial: Bool = false) throws -> DiagnosticResult {
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
        var snapshot = ContainerProbe.snapshot()
        event("runtime", "Read hardware and OS build; inspected already-loaded symbols without invoking them.")
        let os = ProcessInfo.processInfo.operatingSystemVersion
        var assessment = Compatibility.assessment(
            machine: snapshot["hardwareIdentifier"] as? String ?? "unavailable",
            build: snapshot["osBuild"] as? String ?? "unavailable",
            major: os.majorVersion, minor: os.minorVersion, patch: os.patchVersion,
            simulator: snapshot["simulator"] as? Bool ?? true)
        event("compatibility", "Compared model, version and build against observations; beta release channel remains unverified.")
        let filesystem = filesystemSnapshot()
        event("filesystem", "Performed open/fstat/pread and O_WRONLY open-only check; no system file content modified.")
        let trial: [String: Any] = exploitTrial ? ContainerProbe.runEscapeTrial() : ["status": "notRequested"]
        if exploitTrial {
            snapshot["privateAPIsInvoked"] = true
            snapshot["containerQueriesSent"] = true
            let strategies = trial["strategies"] as? [[String: Any]] ?? []
            snapshot["sandboxExtensionsConsumed"] = strategies.contains { ($0["tokenConsumed"] as? Bool) == true }
            snapshot["appGroupLookupPerformed"] = true
            let verified = (trial["status"] as? String) == "sandboxEscapeVerified"
            assessment["vulnerabilityStatus"] = verified ? "sandboxEscapeVerified" : "notVerifiedByTestedStrategies"
            event("exploit", "MCM strategies evaluated with preflight; class 7 skipped if dedicated signed App Group unavailable. No system writes.")
        }
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
            "runtime": snapshot, "filesystem": filesystem, "compatibility": assessment, "events": events,
            "sandboxEscapeTrial": trial,
            "reference": ["repository": "https://github.com/forcequitOS/worse_query",
                          "commit": "d1540e20cd82b974d891e0551ced6d6aeb570ac2"],
            "exploitResearchSources": [
                "https://github.com/0xjohnnydev/Geod-MCM-PoC",
                "https://github.com/murk-sus/kamui-escape"
            ],
            "scope": ["systemFilesModified": false, "foreignContainersEnumerated": false,
                      "newPrivateLibrariesLoaded": false, "networkRequests": false,
            "filesystemReadChecks": "open/fstat; pread up to 16 bytes; O_WRONLY open-only without O_CREAT/O_TRUNC/write; no content exported or modified",
                      "writes": "Only this application's A16ProbeReports directory",
                      "deviceTestConclusion": exploitTrial ? "MCM query trial attempted; success only if denied->allowed->denied write-open proved" : "Exploit trial not requested"]
        ]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        logger.info("Report saved in application sandbox.")
        return DiagnosticResult(text: String(decoding: data, as: UTF8.self), file: file)
    }
    // Observe the actual sandbox boundary through benign open/close calls only.
    // An ENOENT result cannot distinguish a nonexistent path from a hidden one.
    private static func filesystemSnapshot() -> [String: Any] {
        let fm = FileManager.default
        let documents = fm.urls(for: .documentDirectory, in: .userDomainMask).first
        func check(_ name: String, _ path: String) -> [String: Any] {
            let descriptor = path.withCString { Darwin.open($0, O_RDONLY | O_CLOEXEC) }
            if descriptor >= 0 {
                var metadata = stat()
                let metadataStatus = Darwin.fstat(descriptor, &metadata)
                let metadataError = metadataStatus == 0 ? 0 : errno
                if metadataStatus != 0 {
                    _ = Darwin.close(descriptor)
                    return ["name": name, "status": "openSucceeded", "errno": 0,
                            "fstatStatus": "failed", "fstatErrno": Int(metadataError),
                            "interpretation": "Handle opened but fstat failed; contents not read."]
                }
                let kind = metadata.st_mode & 0o170000
                let fileType: String
                switch kind {
                case 0o100000: fileType = "regularFile"
                case 0o040000: fileType = "directory"
                case 0o120000: fileType = "symbolicLink"
                default: fileType = "other"
                }
                var readProbe: [String: Any] = ["attempted": false]
                if name == "mobileGestaltCachePath" && fileType == "regularFile" {
                    // Read at most 16 bytes into ephemeral memory. Never include bytes in JSON or logs.
                    var prefix = [UInt8](repeating: 0, count: 16)
                    let count = prefix.withUnsafeMutableBytes { buffer in
                        Darwin.pread(descriptor, buffer.baseAddress, buffer.count, 0)
                    }
                    if count >= 0 {
                        readProbe = ["attempted": true, "status": "readSucceeded",
                                     "bytesRead": Int(count), "contentExported": false]
                    } else {
                        let code = errno
                        readProbe = ["attempted": true, "status": "readFailed",
                                     "errno": Int(code), "error": String(cString: strerror(code)),
                                     "contentExported": false]
                    }
                    prefix = [UInt8](repeating: 0, count: 16)
                }
                _ = Darwin.close(descriptor)
                var writeOpenProbe: [String: Any] = ["attempted": false]
                if name == "mobileGestaltCachePath" && fileType == "regularFile" {
                    // O_WRONLY without O_CREAT, O_TRUNC or write/pwrite: checks open permission only.
                    let writeDescriptor = path.withCString {
                        Darwin.open($0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW)
                    }
                    if writeDescriptor >= 0 {
                        _ = Darwin.close(writeDescriptor)
                        writeOpenProbe = ["attempted": true, "status": "writeOpenSucceeded",
                                          "fileModified": false,
                                          "interpretation": "Write-only descriptor opened; no writes attempted."]
                    } else {
                        let code = errno
                        writeOpenProbe = ["attempted": true, "status": "writeOpenFailed",
                                          "errno": Int(code), "error": String(cString: strerror(code)),
                                          "fileModified": false,
                                          "interpretation": "Write-only open was rejected; no writes attempted."]
                    }
                }
                return ["name": name, "status": "openSucceeded", "errno": 0,
                        "fstatStatus": "success", "fileType": fileType,
                        "fileSizeBytes": Int64(metadata.st_size), "readProbe": readProbe,
                        "writeOpenProbe": writeOpenProbe,
                        "interpretation": "File opened for reading and inspected; write-open result is separate from actual modification."]
            }
            let code = errno
            let detail = String(cString: strerror(code))
            return ["name": name, "status": "openFailed", "errno": Int(code),
                    "error": detail,
                    "interpretation": code == ENOENT
                        ? "Path missing or hidden; access cannot be inferred."
                        : (code == EACCES || code == EPERM)
                            ? "Open denied in this process context."
                            : "No access conclusion from this error alone."]
        }
        var observations: [[String: Any]] = [
            check("ownBundleDirectory", Bundle.main.bundleURL.path),
            check("systemGroupDirectory", "/private/var/containers/Shared/SystemGroup"),
            check("mobileGestaltCachePath",
                  "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist")
        ]
        if let documents {
            observations.insert(check("ownDocumentsDirectory", documents.path), at: 1)
            let impossible = documents.appendingPathComponent("missing-a16probe-\(UUID().uuidString)")
            observations.append(check("missingFileControl", impossible.path))
        }

        // App Group access is meaningful only when a real group ID is configured
        // and the signing profile actually grants its entitlement.
        var groupInfo: [String: Any] = ["configured": false, "lookupPerformed": false,
                                      "interpretation": "No group ID configured; do not treat this as a denial."]
        if let identifier = Bundle.main.object(forInfoDictionaryKey: "A16ProbeAppGroupIdentifier") as? String,
           !identifier.isEmpty {
            let url = fm.containerURL(forSecurityApplicationGroupIdentifier: identifier)
            groupInfo = ["configured": true, "lookupPerformed": true,
                         "lookupSucceeded": url != nil,
                         "interpretation": url == nil
                             ? "No group URL returned; check signing entitlements before interpreting."
                             : "Own App Group URL returned; not evidence of access to another group."]
        }
        return ["mode": "openReadAndNonModifyingWriteOpen", "paths": observations,
                "appGroup": groupInfo,
                "limits": "No enumeration, symlinks, private APIs or system modification. Read or write-open success does not establish a sandbox escape."]
    }

}

import Foundation

struct Compatibility {
    static func assessment(machine: String, build: String, major: Int, minor: Int, patch: Int,
                           simulator: Bool) -> [String: String] {
        let hardware = simulator ? "simulator" : (machine == "iPhone15,3" ? "matches" : "doesNotMatch")
        let osMatches = major == 27 && minor == 3 && patch == 0
        let buildMatch: String
        if simulator {
            buildMatch = "notApplicableSimulator"
        } else if build == "24C5037i" {
            buildMatch = "matchesObservedDeviceBuild; beta label not independently verified"
        } else if build == "unavailable" {
            buildMatch = "unavailable"
        } else {
            buildMatch = "doesNotMatchObservedDeviceBuild"
        }
        return [
            "requestedDevice": "iPhone 14 Pro Max (iPhone15,3 / A16)",
            "requestedOS": "iOS 27.3 beta 1",
            "hardwareMatch": hardware,
            "numericOSMatch": osMatches ? "matches" : "doesNotMatch",
            "betaBuildMatch": buildMatch,
            "buildReference": "24C5037i observed in the first device JSON; not independent Apple verification",
            "vulnerabilityStatus": "notTested",
            "interpretation": "Symbol visibility does not establish ABI compatibility, authorization, or vulnerability."
        ]
    }
}

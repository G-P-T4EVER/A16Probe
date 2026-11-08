import Foundation

struct Compatibility {
    static func assessment(machine: String, major: Int, minor: Int, patch: Int,
                           simulator: Bool) -> [String: String] {
        let hardware = simulator ? "simulator" : (machine == "iPhone15,3" ? "matches" : "doesNotMatch")
        let osMatches = major == 27 && minor == 3 && patch == 0
        return [
            "requestedDevice": "iPhone 14 Pro Max (iPhone15,3 / A16)",
            "requestedOS": "iOS 27.3 beta 1",
            "hardwareMatch": hardware,
            "numericOSMatch": osMatches ? "matches" : "doesNotMatch",
            "betaBuildMatch": "unverified: no trusted beta 1 build identifier supplied",
            "vulnerabilityStatus": "notTested",
            "interpretation": "Symbol visibility does not establish ABI compatibility, authorization, or vulnerability."
        ]
    }
}

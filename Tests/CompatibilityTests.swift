import Foundation

@main
struct CompatibilityTests {
    static func main() {
        let target = Compatibility.assessment(machine: "iPhone15,3", build: "24C5037i", major: 27, minor: 3, patch: 0, simulator: false)
        precondition(target["hardwareMatch"] == "matches")
        precondition(target["numericOSMatch"] == "matches")
        precondition(target["vulnerabilityStatus"] == "notTested")
        precondition(target["betaBuildMatch"]!.hasPrefix("matchesObservedDeviceBuild"))
        precondition(target["vulnerabilityStatus"] == "notTested")
        let simulator = Compatibility.assessment(machine: "iPhone15,3", build: "24C5037i", major: 27, minor: 3, patch: 0, simulator: true)
        precondition(simulator["hardwareMatch"] == "simulator")
        precondition(simulator["betaBuildMatch"] == "notApplicableSimulator")
        let other = Compatibility.assessment(machine: "iPhone15,2", build: "24B119", major: 27, minor: 2, patch: 0, simulator: false)
        precondition(other["hardwareMatch"] == "doesNotMatch")
        precondition(other["numericOSMatch"] == "doesNotMatch")
        precondition(other["betaBuildMatch"] == "doesNotMatchObservedDeviceBuild")
        let patch = Compatibility.assessment(machine: "unknown", build: "unavailable", major: 27, minor: 3, patch: 1, simulator: false)
        precondition(patch["numericOSMatch"] == "doesNotMatch")
        precondition(patch["betaBuildMatch"] == "unavailable")
        print("Compatibility tests passed (4 scenarios, build coverage).")
    }
}

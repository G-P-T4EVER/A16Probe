import Foundation

@main
struct CompatibilityTests {
    static func main() {
        let target = Compatibility.assessment(machine: "iPhone15,3", major: 27, minor: 3, patch: 0, simulator: false)
        precondition(target["hardwareMatch"] == "matches")
        precondition(target["numericOSMatch"] == "matches")
        precondition(target["vulnerabilityStatus"] == "notTested")
        precondition(target["betaBuildMatch"]!.hasPrefix("unverified"))
        let simulator = Compatibility.assessment(machine: "iPhone15,3", major: 27, minor: 3, patch: 0, simulator: true)
        precondition(simulator["hardwareMatch"] == "simulator")
        let other = Compatibility.assessment(machine: "iPhone15,2", major: 27, minor: 2, patch: 0, simulator: false)
        precondition(other["hardwareMatch"] == "doesNotMatch")
        precondition(other["numericOSMatch"] == "doesNotMatch")
        let patch = Compatibility.assessment(machine: "unknown", major: 27, minor: 3, patch: 1, simulator: false)
        precondition(patch["numericOSMatch"] == "doesNotMatch")
        print("Compatibility tests passed (4 scenarios).")
    }
}

import Foundation

/// The tiny slice the watch app hands to its face complication: the fleet's
/// latest burn rate and whether any run is over cap. Shared through an app group
/// so the complication can render without opening the app.
enum FaceStore {
    static let group = "group.com.taipanbox.tokenfuse"

    private static var defaults: UserDefaults? { UserDefaults(suiteName: group) }

    static func save(rate: Double, overCap: Bool) {
        defaults?.set(rate, forKey: "fleetRate")
        defaults?.set(overCap, forKey: "fleetOverCap")
    }

    static func load() -> (rate: Double, overCap: Bool) {
        (defaults?.double(forKey: "fleetRate") ?? 0,
         defaults?.bool(forKey: "fleetOverCap") ?? false)
    }
}

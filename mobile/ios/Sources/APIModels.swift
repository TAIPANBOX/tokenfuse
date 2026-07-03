import Foundation

// Typed models mirroring the control-plane contract (mobile/ios/openapi.json,
// generated from crates/cloud). Decoded with `.convertFromSnakeCase`, so the
// wire's `run_id` / `spent_microusd` map to these camelCase properties. Money
// is microdollars on the wire; converted to dollars for display.

struct RunAgg: Codable, Identifiable, Sendable, Hashable {
    let runId: String
    let model: String
    let spentMicrousd: Int64
    let calls: Int
    let cacheHits: Int
    let steps: Int
    let lastSeenMillis: Int64
    let killed: Bool

    var id: String { runId }
}

struct Summary: Codable, Sendable {
    let runs: Int
    let calls: Int
    let spentMicrousd: Int64
}

/// One time bucket of the burn-rate series (`/v1/series`).
struct SeriesBucket: Codable, Sendable, Identifiable {
    let t: Int64  // bucket start, epoch millis
    let costMicrousd: Int64
    let calls: Int
    let blocked: Int

    var id: Int64 { t }
    var cost: Double { costMicrousd.usd }
}

extension Int64 {
    /// Microdollars → dollars.
    var usd: Double { Double(self) / 1_000_000 }
}

extension Array where Element == SeriesBucket {
    /// Recent burn rate in $/min — the last non-empty bucket, scaled to a minute.
    func burnRatePerMin(stepSeconds: Double) -> Double {
        guard let last = last(where: { $0.costMicrousd > 0 }) else { return 0 }
        return last.cost / (stepSeconds / 60)
    }
}

import Foundation

/// A run's aggregate — the mobile mirror of the control plane's `RunAgg`
/// (crates/cloud). Money is in dollars here for display; the API speaks
/// microdollars. Replaced by the generated OpenAPI model in B2.
struct Run: Identifiable, Sendable {
    let id: String
    let model: String
    let spent: Double
    let budget: Double
    let ratePerMin: Double
    let steps: Int

    var fraction: Double { budget > 0 ? spent / budget : 0 }
}

extension Run {
    /// Sample fleet — matches the design mockups so the first screen reads true.
    static let sample: [Run] = [
        Run(id: "7f3a2b", model: "opus-4-8", spent: 26.10, budget: 25.00, ratePerMin: 1.90, steps: 41),
        Run(id: "b12e90", model: "sonnet", spent: 8.40, budget: 10.00, ratePerMin: 0.31, steps: 18),
        Run(id: "9d1c77", model: "gpt-4", spent: 3.00, budget: 12.00, ratePerMin: 0.12, steps: 11),
        Run(id: "4c07af", model: "haiku", spent: 1.20, budget: 8.00, ratePerMin: 0.06, steps: 6),
    ]
}

import Foundation
import Observation

/// A run joined with its central budget, ready for display.
struct RunDisplay: Identifiable, Sendable {
    let agg: RunAgg
    let budgetMicros: Int64?

    var id: String { agg.runId }
    var killed: Bool { agg.killed }
    var spent: Double { agg.spentMicrousd.usd }
    var budget: Double? { budgetMicros?.usd }
    var hasBudget: Bool { (budgetMicros ?? 0) > 0 }
    /// spent / budget, or 0 when no budget is set (fuse renders neutral).
    var fraction: Double {
        guard let b = budgetMicros, b > 0 else { return 0 }
        return Double(agg.spentMicrousd) / Double(b)
    }
}

/// Loads the fleet from the control plane and shapes it for the Runs screen.
@MainActor
@Observable
final class RunsStore {
    enum Phase: Equatable {
        case idle, loading, loaded, failed(String)
    }

    private(set) var phase: Phase = .idle
    private(set) var runs: [RunDisplay] = []
    private(set) var summary: Summary?
    private(set) var totalCapsMicros: Int64 = 0

    var totalCaps: Double { totalCapsMicros.usd }

    func load(using client: APIClient) async {
        if phase != .loaded { phase = .loading }
        do {
            async let runsReq = client.runs()
            async let summaryReq = client.summary()
            async let budgetsReq = client.budgets()
            let (runs, summary, budgets) = try await (runsReq, summaryReq, budgetsReq)

            self.summary = summary
            self.totalCapsMicros = budgets.values.reduce(0, +)
            self.runs = runs
                .map { RunDisplay(agg: $0, budgetMicros: budgets[$0.runId]) }
                .sorted { $0.fraction > $1.fraction }
            self.phase = .loaded
        } catch {
            self.phase = .failed(error.localizedDescription)
        }
    }
}

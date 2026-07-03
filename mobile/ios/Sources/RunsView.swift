import SwiftUI

/// The home deck, live from a control plane: spent-today hero + fuse, then every
/// run as a fuse — hottest first, the over-cap run in ember. Pull to refresh.
/// (Per-run and fleet $/min join in B6, once the series endpoint is wired.)
struct RunsView: View {
    let client: APIClient
    var onDisconnect: () -> Void

    @State private var store = RunsStore()

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    if case .failed(let message) = store.phase {
                        errorCard(message)
                    }
                    if let summary = store.summary {
                        heroCard(summary)
                    }
                    ForEach(store.runs) { RunRow(run: $0) }
                    footerState
                }
                .padding(18)
            }
        }
        .task { await store.load(using: client) }
        .refreshable { await store.load(using: client) }
        .foregroundStyle(Palette.fg)
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Runs").font(.instrument(32))
                HStack(spacing: 7) {
                    Circle().fill(store.phase == .loaded ? Palette.mint : Palette.faint)
                        .frame(width: 6, height: 6)
                    Text(client.baseURL.host() ?? "plane")
                        .font(.mono).foregroundStyle(Palette.dim)
                }
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(Palette.panel, in: Capsule())
                .overlay(Capsule().stroke(Palette.line))
            }
            Spacer()
            Button(action: onDisconnect) {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Palette.iris)
                    .padding(9)
                    .background(Palette.panel, in: Circle())
                    .overlay(Circle().stroke(Palette.line))
            }
            .accessibilityLabel("Change plane")
        }
    }

    private func heroCard(_ summary: Summary) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SPENT TODAY")
                .font(.system(size: 10, weight: .semibold)).tracking(2)
                .foregroundStyle(Palette.faint)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(usd(summary.spentMicrousd.usd))
                    .font(.instrument(46)).monospacedDigit()
                Spacer()
                Text("\(summary.runs) runs · \(summary.calls) calls")
                    .font(.mono).foregroundStyle(Palette.dim)
            }
            if store.totalCapsMicros > 0 {
                Fuse(fraction: summary.spentMicrousd.usd / store.totalCaps)
                HStack {
                    Text("caps \(usd(store.totalCaps))")
                    Spacer()
                    Text("\(Int((summary.spentMicrousd.usd / store.totalCaps * 100).rounded()))%")
                }
                .font(.mono).foregroundStyle(Palette.dim)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.panel, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(Palette.line))
    }

    private func errorCard(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("CAN'T REACH THE PLANE").font(.system(size: 10, weight: .semibold)).tracking(1.6)
                .foregroundStyle(Palette.ember)
            Text(message).font(.mono).foregroundStyle(Palette.dim)
            Button("Retry") { Task { await store.load(using: client) } }
                .font(.system(size: 13, weight: .semibold)).foregroundStyle(Palette.iris)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.ember.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Palette.ember.opacity(0.3)))
    }

    @ViewBuilder private var footerState: some View {
        if store.phase == .loading && store.runs.isEmpty {
            ProgressView().tint(Palette.iris).frame(maxWidth: .infinity).padding(.top, 40)
        } else if store.phase == .loaded && store.runs.isEmpty {
            Text("No runs yet. Send traffic through a gateway and they'll appear here.")
                .font(.mono).foregroundStyle(Palette.faint)
                .frame(maxWidth: .infinity, alignment: .center).padding(.top, 40)
        }
    }

    private func usd(_ value: Double) -> String { String(format: "$%.2f", value) }
}

/// One run: id + status, model/steps + spend, and its fuse (when a cap is set).
struct RunRow: View {
    let run: RunDisplay

    var body: some View {
        let heat = Heat.of(fraction: run.fraction)
        let over = run.killed ? false : (run.hasBudget && heat == .over)
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(run.agg.runId).font(.system(.callout, design: .monospaced))
                statusPill(heat: heat)
                Spacer()
                Text("$\(String(format: "%.2f", run.spent))")
                    .font(.mono).foregroundStyle(run.killed ? Palette.dim : Palette.fg)
            }
            HStack {
                Text("\(run.agg.model.isEmpty ? "—" : run.agg.model) · step \(run.agg.steps)")
                    .font(.mono).foregroundStyle(Palette.dim)
                Spacer()
                if let budget = run.budget {
                    Text("cap $\(String(format: "%.2f", budget))")
                        .font(.mono).foregroundStyle(Palette.dim)
                }
            }
            if run.hasBudget {
                Fuse(fraction: run.fraction)
            } else {
                Text("no cap set").font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(Palette.faint)
            }
        }
        .padding(12)
        .background(
            over ? AnyShapeStyle(Palette.ember.opacity(0.06))
                 : AnyShapeStyle(Palette.panel.opacity(0.4)),
            in: RoundedRectangle(cornerRadius: 16)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(over ? Palette.ember.opacity(0.35) : Palette.line)
        )
        .opacity(run.killed ? 0.55 : 1)
    }

    @ViewBuilder private func statusPill(heat: Heat) -> some View {
        if run.killed {
            pill(text: "killed", color: Palette.faint)
        } else if run.hasBudget {
            StatusPill(heat: heat)
        } else {
            pill(text: "live", color: Palette.mint)
        }
    }

    private func pill(text: String, color: Color) -> some View {
        Text(text.uppercased())
            .font(.system(size: 9, weight: .semibold)).tracking(0.6)
            .foregroundStyle(color)
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(color.opacity(0.1), in: Capsule())
            .overlay(Capsule().stroke(color.opacity(0.3)))
    }
}

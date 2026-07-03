import SwiftUI

/// The home deck: fleet burn rate up top, then every run as a fuse — hottest
/// first. The first screen that proves the design direction in SwiftUI.
struct RunsView: View {
    private let runs = Run.sample

    private var fleetBurn: Double { runs.map(\.ratePerMin).reduce(0, +) }
    private var spent: Double { runs.map(\.spent).reduce(0, +) }
    private var caps: Double { runs.map(\.budget).reduce(0, +) }
    private var sortedRuns: [Run] { runs.sorted { $0.fraction > $1.fraction } }

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    heroCard
                    ForEach(sortedRuns) { RunRow(run: $0) }
                }
                .padding(18)
            }
        }
        .foregroundStyle(Palette.fg)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Runs").font(.instrument(32))
            HStack(spacing: 7) {
                Circle().fill(Palette.mint).frame(width: 6, height: 6)
                Text("acme · 3 gateways · live")
                    .font(.mono).foregroundStyle(Palette.dim)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Palette.panel, in: Capsule())
            .overlay(Capsule().stroke(Palette.line))
        }
    }

    private var heroCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("FLEET BURN RATE")
                .font(.system(size: 10, weight: .semibold)).tracking(2)
                .foregroundStyle(Palette.faint)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(String(format: "%.2f", fleetBurn))
                    .font(.instrument(46)).monospacedDigit()
                Text("$/min").font(.mono).foregroundStyle(Palette.amber)
            }
            Fuse(fraction: spent / caps)
            HStack {
                Text("spent $\(String(format: "%.2f", spent))")
                Spacer()
                Text("caps $\(String(format: "%.2f", caps))")
            }
            .font(.mono).foregroundStyle(Palette.dim)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Palette.panel, in: RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(Palette.line))
    }
}

/// One run: id + status + rate, model + spend, and its fuse.
struct RunRow: View {
    let run: Run

    var body: some View {
        let heat = Heat.of(fraction: run.fraction)
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(run.id).font(.system(.callout, design: .monospaced))
                StatusPill(heat: heat)
                Spacer()
                Text("$\(String(format: "%.2f", run.ratePerMin))/m")
                    .font(.mono).foregroundStyle(heat.accent)
            }
            HStack {
                Text("\(run.model) · step \(run.steps)")
                    .font(.mono).foregroundStyle(Palette.dim)
                Spacer()
                Text("$\(String(format: "%.2f", run.spent)) / $\(String(format: "%.2f", run.budget))")
                    .font(.mono).foregroundStyle(Palette.fg)
            }
            Fuse(fraction: run.fraction)
        }
        .padding(12)
        .background(
            heat == .over ? AnyShapeStyle(Palette.ember.opacity(0.06))
                          : AnyShapeStyle(Palette.panel.opacity(0.4)),
            in: RoundedRectangle(cornerRadius: 16)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(heat == .over ? Palette.ember.opacity(0.35) : Palette.line)
        )
    }
}

#Preview {
    RunsView().preferredColorScheme(.dark)
}

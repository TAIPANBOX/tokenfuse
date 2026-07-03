import SwiftUI

/// The kill switch on the wrist: the run's spend and fuse, then a single red
/// button. The kill is **signed on this Apple Watch** by its own device key —
/// enforced across every gateway. On success it flips to the "Killed" seal.
struct WatchRunKillView: View {
    let run: RunDisplay
    let account: Account
    var onKilled: () async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var killed = false
    @State private var error: String?

    private var over: Bool {
        !run.killed && run.hasBudget && Heat.of(fraction: run.fraction) == .over
    }

    var body: some View {
        ScrollView {
            if killed {
                seal
            } else {
                VStack(spacing: 10) {
                    Text(run.agg.runId)
                        .font(.system(size: 14, design: .monospaced))
                        .foregroundStyle(Palette.dim)
                    Text("$\(String(format: "%.2f", run.spent))")
                        .font(.system(size: 34, weight: .heavy)).monospacedDigit()
                        .foregroundStyle(over ? Palette.ember : Palette.fg)
                    if run.hasBudget { Fuse(fraction: run.fraction, height: 7) }

                    if run.killed {
                        Text("Already killed")
                            .font(.system(size: 12)).foregroundStyle(Palette.faint)
                    } else {
                        Button(action: kill) {
                            HStack(spacing: 6) {
                                if busy { ProgressView().tint(.white) }
                                Text(busy ? "Killing…" : "Kill run")
                                    .font(.system(size: 16, weight: .bold))
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(Palette.ember)
                        .disabled(busy)

                        if let error {
                            Text(error).font(.system(size: 11)).foregroundStyle(Palette.ember)
                        }
                        Text("Signed on this Apple Watch")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Palette.faint)
                    }
                }
                .padding(.top, 4)
            }
        }
        .containerBackground(Palette.ink.gradient, for: .navigation)
        .task {
            // UI-check hook: fire the signed kill automatically (simulator only).
            if LaunchArgs.has("-autoKill"), !run.killed, !busy, !killed { kill() }
        }
    }

    private var seal: some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 42)).foregroundStyle(Palette.mint)
            Text("Killed").font(.system(size: 22, weight: .bold))
            Text(run.agg.runId)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(Palette.dim)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 20)
    }

    private func kill() {
        busy = true
        error = nil
        Task {
            do {
                try await account.kill(run: run.id)
                killed = true
                await onKilled()
                try? await Task.sleep(for: .seconds(1.3))
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
            busy = false
        }
    }
}

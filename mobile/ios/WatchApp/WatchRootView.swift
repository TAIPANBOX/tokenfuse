import SwiftUI

/// Entry point: restore a paired session (own signing key) and show the fleet;
/// otherwise a short "pair on your iPhone" note. For the simulator the watch can
/// bootstrap itself from launch args (`-autoPairURL` / `-autoPairCode`); W4 will
/// hand the session over from the paired iPhone via WatchConnectivity.
struct WatchRootView: View {
    @State private var account: Account?
    @State private var pairing = false
    @State private var error: String?

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            if let account {
                WatchFleetView(account: account)
            } else {
                unpaired
            }
        }
        .foregroundStyle(Palette.fg)
        .task { await bootstrap() }
    }

    private var unpaired: some View {
        VStack(spacing: 10) {
            BrandMark(size: 46)
            if pairing {
                ProgressView().tint(Palette.mint)
            } else {
                Text(error ?? "Open TokenFuse on your iPhone to pair, then it appears here.")
                    .font(.system(size: 13))
                    .multilineTextAlignment(.center)
                    .foregroundStyle(error == nil ? Palette.dim : Palette.ember)
            }
        }
        .padding()
    }

    private func bootstrap() async {
        if let (session, key) = SessionStore.load() {
            account = Account(session: session, key: key)
            return
        }
        guard let url = LaunchArgs.value("-autoPairURL"),
              let code = LaunchArgs.value("-autoPairCode") else { return }
        pairing = true
        defer { pairing = false }
        do {
            let (session, key) = try await PairingService.pair(
                planeURL: url, code: code, deviceName: "Apple Watch", platform: "watchos")
            SessionStore.save(session, key: key)
            account = Account(session: session, key: key)
        } catch {
            self.error = error.localizedDescription
        }
    }
}

import SwiftUI

/// Decides between connecting to a plane and showing the fleet. Config lives in
/// `@AppStorage` for now; pairing + Keychain replace the org key in B3.
struct RootView: View {
    @AppStorage("planeURL") private var planeURL = ""
    @AppStorage("orgKey") private var orgKey = ""

    var body: some View {
        if let client {
            RunsView(client: client, onDisconnect: disconnect)
        } else {
            ConnectView()
        }
    }

    private var client: APIClient? {
        guard !planeURL.isEmpty, !orgKey.isEmpty,
              let url = URL(string: planeURL), url.scheme != nil
        else { return nil }
        return APIClient(baseURL: url, token: orgKey)
    }

    private func disconnect() {
        planeURL = ""
        orgKey = ""
    }
}

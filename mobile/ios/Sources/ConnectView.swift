import SwiftUI

/// First-run connect: point the app at a control plane. The org key is stored in
/// `@AppStorage` as a stepping stone — B3 replaces it with a paired device token
/// held in the Keychain.
struct ConnectView: View {
    @AppStorage("planeURL") private var planeURL = ""
    @AppStorage("orgKey") private var orgKey = ""

    @State private var url = "http://localhost:4100"
    @State private var key = ""

    var body: some View {
        ZStack {
            Palette.ink.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 20) {
                Spacer()
                brand
                VStack(alignment: .leading, spacing: 14) {
                    field(label: "PLANE URL", text: $url, placeholder: "https://…", mono: true)
                    field(label: "ORG KEY", text: $key, placeholder: "devkey", mono: true, secure: true)
                }
                Button(action: connect) {
                    Text("Connect")
                        .font(.system(size: 16, weight: .bold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Palette.iris, in: RoundedRectangle(cornerRadius: 14))
                        .foregroundStyle(.white)
                }
                .disabled(url.isEmpty || key.isEmpty)
                .opacity(url.isEmpty || key.isEmpty ? 0.5 : 1)

                Text("Keys never leave this iPhone. Kills will be signed by the Secure Enclave.")
                    .font(.mono).foregroundStyle(Palette.faint)
                Spacer()
            }
            .padding(22)
        }
        .foregroundStyle(Palette.fg)
    }

    private var brand: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("TokenFuse Pocket").font(.instrument(30))
            Text("Hold the breaker on your agents.")
                .font(.system(size: 15)).foregroundStyle(Palette.dim)
        }
    }

    private func field(label: String, text: Binding<String>, placeholder: String, mono: Bool, secure: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(label).font(.system(size: 10, weight: .semibold)).tracking(1.6)
                .foregroundStyle(Palette.faint)
            Group {
                if secure {
                    SecureField(placeholder, text: text)
                } else {
                    TextField(placeholder, text: text)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                }
            }
            .font(mono ? .system(.body, design: .monospaced) : .body)
            .padding(12)
            .background(Palette.panel, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Palette.line))
        }
    }

    private func connect() {
        planeURL = url
        orgKey = key
    }
}

#Preview {
    ConnectView().preferredColorScheme(.dark)
}

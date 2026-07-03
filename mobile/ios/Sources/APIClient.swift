import Foundation

/// A thin typed client for the TokenFuse Cloud control plane. Reads use a bearer
/// token (org key today; a paired device token in B3). Kept deliberately small
/// and dependency-free; it mirrors mobile/ios/openapi.json.
struct APIClient: Sendable {
    let baseURL: URL
    let token: String
    let session: URLSession

    init(baseURL: URL, token: String, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.token = token
        self.session = session
    }

    enum ClientError: LocalizedError {
        case http(Int)
        case notHTTP

        var errorDescription: String? {
            switch self {
            case .http(let code): return "The plane returned HTTP \(code)."
            case .notHTTP: return "No response from the plane."
            }
        }
    }

    private func get<T: Decodable>(_ path: String) async throws -> T {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ClientError.notHTTP }
        guard (200..<300).contains(http.statusCode) else { throw ClientError.http(http.statusCode) }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(T.self, from: data)
    }

    func runs() async throws -> [RunAgg] { try await get("v1/runs") }
    func summary() async throws -> Summary { try await get("v1/summary") }
    func budgets() async throws -> [String: Int64] { try await get("v1/budgets") }
}

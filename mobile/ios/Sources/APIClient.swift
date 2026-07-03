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

    private func get<T: Decodable>(_ path: String, query: [URLQueryItem] = []) async throws -> T {
        var components = URLComponents(url: baseURL.appending(path: path), resolvingAgainstBaseURL: false)!
        if !query.isEmpty { components.queryItems = query }
        var request = URLRequest(url: components.url!)
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

    /// Burn-rate buckets for the whole org (`run == nil`) or a single run.
    func series(run: String?, window: String, step: String) async throws -> [SeriesBucket] {
        var query = [URLQueryItem(name: "window", value: window), URLQueryItem(name: "step", value: step)]
        if let run { query.append(URLQueryItem(name: "run", value: run)) }
        return try await get("v1/series", query: query)
    }
}

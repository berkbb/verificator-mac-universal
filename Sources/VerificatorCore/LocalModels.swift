// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationModels)
import FoundationModels
#endif

/// Öneri ve adli yorum modelinin sağlayıcısı: Apple Intelligence, bu Mac'te çalışan yerel bir model sunucusu
/// ya da "Otomatik" (seçilen sırayla, ilk yanıt verebilen; bkz. `FallbackSuggestionModel`).
public enum SuggestionProvider: String, CaseIterable, Identifiable, Sendable {
    case apple, ollama, lmStudio, automatic

    public var id: String { rawValue }
    /// Gerçek sağlayıcılar (Otomatik dışındakiler), varsayılan sırayla (Apple Intelligence birinci).
    public static let models: [SuggestionProvider] = [.apple, .ollama, .lmStudio]

    /// Ürün adı (çevrilmez; Otomatik için boş, arayüz kendi metnini yazar).
    public var displayName: String {
        switch self {
        case .automatic: ""
        case .apple: "Apple Intelligence"
        case .ollama: "Ollama"
        case .lmStudio: "LM Studio"
        }
    }

    /// Yerel sunucu (Apple Intelligence ve Otomatik için nil).
    public var server: LocalModelServer? {
        switch self {
        case .automatic, .apple: nil
        case .ollama: .ollama
        case .lmStudio: .lmStudio
        }
    }

    /// Kaydedilmiş sıradan geçerli bir sıra: her gerçek sağlayıcı bir kez; bilinmeyenler atılır, eksikler sona eklenir.
    public static func order(_ raw: [String]) -> [SuggestionProvider] {
        var order: [SuggestionProvider] = []
        for value in raw {
            if let provider = SuggestionProvider(rawValue: value), provider != .automatic, !order.contains(provider) {
                order.append(provider)
            }
        }
        return order + models.filter { !order.contains($0) }
    }
}

/// Yalnızca bu Mac'te çalışan dil modeli protokolü: Apple Intelligence cihaz üstü modeli
/// ya da 127.0.0.1'deki yerel bir sunucu (Ollama, LM Studio). Bulut modelleri ve dış hizmetler kullanılmaz.
public protocol SuggestionModel: Sendable {
    var isAvailable: Bool { get }
    func respond(instructions: String, prompt: String) async throws -> String
}

/// macOS cihaz üstü dil modeli (Foundation Models, `SystemLanguageModel.default`).
public struct OnDeviceSuggestionModel: SuggestionModel {
    public init() {}

    public var isAvailable: Bool {
        #if canImport(FoundationModels)
        if case .available = SystemLanguageModel.default.availability { return true }
        #endif
        return false
    }

    public func respond(instructions: String, prompt: String) async throws -> String {
        #if canImport(FoundationModels)
        let session = LanguageModelSession(model: SystemLanguageModel.default, instructions: instructions)
        return try await session.respond(to: prompt, options: GenerationOptions(samplingMode: .greedy)).content
        #else
        throw LocalModelServer.Failure.unavailable
        #endif
    }
}

/// "Otomatik": modeller sırayla denenir. Kullanılabilir ilk model sorulur; erişilemezse veya hata verirse sıradaki denenir.
public final class FallbackSuggestionModel: SuggestionModel, @unchecked Sendable {
    public let members: [(name: String, model: any SuggestionModel)]
    private let lock = NSLock()
    private var answered: String?

    public init(_ members: [(name: String, model: any SuggestionModel)]) {
        self.members = members
    }

    public var isAvailable: Bool { members.contains { $0.model.isAvailable } }

    /// Son geçerli yanıtı veren modelin adı.
    public var lastSource: String? { lock.withLock { answered } }

    func record(_ name: String) { lock.withLock { answered = name } }

    public func respond(instructions: String, prompt: String) async throws -> String {
        for member in members where member.model.isAvailable {
            if let answer = try? await member.model.respond(instructions: instructions, prompt: prompt) {
                let cleaned = answer.trimmingCharacters(in: .whitespacesAndNewlines)
                if !cleaned.isEmpty {
                    record(member.name)
                    return cleaned
                }
            }
        }
        throw LocalModelServer.Failure.unavailable
    }
}

/// Bu Mac'te çalışan yerel model sunucusu (Ollama, LM Studio). Adres sabittir: yalnızca 127.0.0.1 ve sunucunun bilinen
/// portu; vekil sunucu kullanılmaz, yönlendirme izlenmez, önbellek ve çerez tutulmaz.
/// Ollama'nın bulut modelleri (istekleri ollama.com'a iletenler) listelenmez ve kullanılmaz.
public enum LocalModelServer: String, CaseIterable, Identifiable, Sendable {
    case ollama, lmStudio

    public var id: String { rawValue }
    /// Ürün adı (çevrilmez).
    public var displayName: String { self == .ollama ? "Ollama" : "LM Studio" }
    public var port: Int { self == .ollama ? 11434 : 1234 }
    var modelsPath: String { self == .ollama ? "/api/tags" : "/v1/models" }
    var chatPath: String { self == .ollama ? "/api/chat" : "/v1/chat/completions" }

    /// Yanıtın en çok boyutu; daha büyüğü reddedilir.
    static let maxResponse = 4_000_000

    public enum Failure: Error, Equatable, Sendable {
        case unavailable, badResponse
    }

    /// Sunucudaki yerel sohbet modelleri (adlarına göre sıralı); sunucu çalışmıyorsa nil.
    public func models(port: Int? = nil) async -> [String]? {
        guard let data = try? await Self.request(modelsPath, port: port ?? self.port, body: nil, timeout: 3) else { return nil }
        return self == .ollama ? Self.ollamaModels(data) : Self.openAIModels(data)
    }

    /// Ollama `/api/tags`: bulut modelleri (`remote_host`, `remote_model` ya da "…-cloud", "…:cloud" adlı) ve sohbet
    /// yeteneği olmayanlar (gömme modelleri) atılır.
    public static func ollamaModels(_ data: Data) -> [String] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let models = root["models"] as? [[String: Any]] else { return [] }
        return models.compactMap { entry -> String? in
            guard let name = (entry["name"] as? String) ?? (entry["model"] as? String), !name.isEmpty else { return nil }
            if entry["remote_host"] != nil || entry["remote_model"] != nil || isCloud(name) { return nil }
            if let capabilities = entry["capabilities"] as? [String], !capabilities.contains("completion") { return nil }
            return name
        }.sorted()
    }

    /// LM Studio `/v1/models` (OpenAI biçimi): gömme modelleri atılır.
    public static func openAIModels(_ data: Data) -> [String] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let models = root["data"] as? [[String: Any]] else { return [] }
        return models.compactMap { entry -> String? in
            guard let id = entry["id"] as? String, !id.isEmpty, !id.lowercased().contains("embed") else { return nil }
            return id
        }.sorted()
    }

    /// Ollama'nın bulut modeli adı ("gpt-oss:120b-cloud", "nemotron-3-ultra:cloud").
    public static func isCloud(_ name: String) -> Bool {
        let lowered = name.lowercased()
        return lowered.hasSuffix("-cloud") || lowered.hasSuffix(":cloud") || lowered.contains("-cloud:")
    }

    public static func ollamaAnswer(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let message = root["message"] as? [String: Any] else { return nil }
        return message["content"] as? String
    }

    public static func openAIAnswer(_ data: Data) -> String? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let choices = root["choices"] as? [[String: Any]], let message = choices.first?["message"] as? [String: Any]
        else { return nil }
        return message["content"] as? String
    }

    /// Düşünen modellerin "<think>…</think>" bölümü atılır (yanıt yalnızca sonuçtur).
    public static func withoutThinking(_ text: String) -> String {
        var result = text
        while let open = result.range(of: "<think>"),
              let close = result.range(of: "</think>", range: open.upperBound..<result.endIndex) {
            result.removeSubrange(open.lowerBound..<close.upperBound)
        }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// 127.0.0.1'e istek: vekil sunucusuz, yönlendirmesiz; yalnızca 200 ve en çok `maxResponse` bayt kabul edilir.
    static func request(_ path: String, port: Int, body: Data?, timeout: TimeInterval) async throws -> Data {
        guard (1...65_535).contains(port), let url = URL(string: "http://127.0.0.1:\(port)\(path)") else {
            throw Failure.unavailable
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        if let body {
            request.httpMethod = "POST"
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: request, delegate: NoRedirects())
        guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url?.host == "127.0.0.1",
              data.count <= maxResponse else { throw Failure.badResponse }
        return data
    }

    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.waitsForConnectivity = false
        return URLSession(configuration: configuration)
    }()

    /// Yönlendirmeler izlenmez: yerel sunucu isteği başka bir adrese (ör. internete) aktaramaz.
    private final class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest
        ) async -> URLRequest? { nil }
    }
}

/// Yerel model sunucusundaki bir modelle yanıt üretir (Ollama `/api/chat`, LM Studio `/v1/chat/completions`).
public struct LocalServerSuggestionModel: SuggestionModel {
    public var server: LocalModelServer
    public var model: String
    /// Model son listede vardı (sunucu çalışıyor ve model yerel).
    public var isAvailable: Bool
    var port: Int

    public init(server: LocalModelServer, model: String, isAvailable: Bool, port: Int? = nil) {
        self.server = server
        self.model = model
        self.isAvailable = isAvailable && !model.isEmpty && !LocalModelServer.isCloud(model)
        self.port = port ?? server.port
    }

    public func respond(instructions: String, prompt: String) async throws -> String {
        guard isAvailable else { throw LocalModelServer.Failure.unavailable }
        var body: [String: Any] = [
            "model": model,
            "messages": [
                ["role": "system", "content": instructions],
                ["role": "user", "content": prompt],
            ],
            "stream": false,
        ]
        if server == .ollama { body["options"] = ["temperature": 0] } else { body["temperature"] = 0 }
        guard JSONSerialization.isValidJSONObject(body) else { throw LocalModelServer.Failure.badResponse }
        let data = try await LocalModelServer.request(
            server.chatPath,
            port: port,
            body: JSONSerialization.data(withJSONObject: body),
            timeout: 60
        )
        guard let answer = server == .ollama ? LocalModelServer.ollamaAnswer(data) : LocalModelServer.openAIAnswer(data)
        else { throw LocalModelServer.Failure.badResponse }
        return LocalModelServer.withoutThinking(answer)
    }
}

/// Yapay zekâ analizi açılırken ön koşulların denetimi.
public enum AIPrerequisites {
    public enum Problem: Equatable, Sendable {
        case deviceNotEligible
        case appleIntelligenceOff
        case modelNotReady
        case appleUnavailable
        case serverNotRunning
        case noLocalModel
        case modelMissing(String)
        case noAnswer
    }

    public struct Check: Equatable, Sendable {
        public var provider: SuggestionProvider
        public var model: String?
        public var problem: Problem?

        public var isReady: Bool { problem == nil }

        public init(provider: SuggestionProvider, model: String? = nil, problem: Problem? = nil) {
            self.provider = provider
            self.model = model
            self.problem = problem
        }
    }

    public static let testTimeout: Duration = .seconds(90)

    /// Apple Intelligence sistem durumu; kullanılabiliyorsa nil.
    public static func appleProblem() -> Problem? {
        #if canImport(FoundationModels)
        switch SystemLanguageModel.default.availability {
        case .available: return nil
        case .unavailable(.deviceNotEligible): return .deviceNotEligible
        case .unavailable(.appleIntelligenceNotEnabled): return .appleIntelligenceOff
        case .unavailable(.modelNotReady): return .modelNotReady
        case .unavailable: return .appleUnavailable
        }
        #else
        return .deviceNotEligible
        #endif
    }

    public static func checkApple(problem: Problem?, model: any SuggestionModel) async -> Check {
        if let problem { return Check(provider: .apple, problem: problem) }
        return await answers(model) ? Check(provider: .apple) : Check(provider: .apple, problem: .noAnswer)
    }

    public static func checkServer(_ server: LocalModelServer, selected: String, port: Int? = nil) async -> Check {
        let provider: SuggestionProvider = server == .ollama ? .ollama : .lmStudio
        guard let models = await server.models(port: port) else {
            return Check(provider: provider, problem: .serverNotRunning)
        }
        guard let first = models.first else {
            return Check(provider: provider, problem: .noLocalModel)
        }
        let name = selected.isEmpty ? first : selected
        guard models.contains(name) else {
            return Check(provider: provider, problem: .modelMissing(name))
        }
        let model = LocalServerSuggestionModel(server: server, model: name, isAvailable: true, port: port)
        return await answers(model)
            ? Check(provider: provider, model: name)
            : Check(provider: provider, model: name, problem: .noAnswer)
    }

    static func answers(_ model: any SuggestionModel) async -> Bool {
        guard let answer = try? await model.respond(
            instructions: "You check that a language model works. Answer with one word.",
            prompt: "Say OK."
        ) else { return false }
        return !answer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Seçili sağlayıcının anlık hazırlık durumunu (sessiz geçiş yapmadan) denetler.
    public static func providerProblem(
        for provider: SuggestionProvider,
        appleProblem: Problem? = Self.appleProblem(),
        runningServers: Set<LocalModelServer>,
        localModels: [LocalModelServer: [String]],
        selectedModel: String
    ) -> Problem? {
        switch provider {
        case .apple:
            return appleProblem
        case .ollama, .lmStudio:
            guard let server = provider.server else { return nil }
            guard runningServers.contains(server) else { return .serverNotRunning }
            let models = localModels[server] ?? []
            guard !models.isEmpty else { return .noLocalModel }
            let chosen = selectedModel.isEmpty ? (models.first ?? "") : selectedModel
            guard models.contains(chosen) else { return .modelMissing(chosen) }
            return nil
        case .automatic:
            return nil
        }
    }
}

/// Deterministik adli raporu (`ForensicReport`) yerel dil modeliyle özetler.
/// Model hiçbir zaman deterministik kararı (`CLEAN` / `WARNING` / `TAMPERED`) değiştirmez; yalnızca mevcut kanıtları açıklar.
public enum ForensicAI {
    public static func instructions(for languageCode: String) -> String {
        let languageName: String = switch languageCode {
        case "tr": "Turkish (Türkçe)"
        case "ro": "Romanian (Română)"
        default: "English"
        }
        return """
        You are an on-device macOS security and Mach-O forensic analyst inside Verificator. \
        You receive a deterministic forensic inspection report for a macOS .app bundle. \
        Do not contradict or alter the deterministic verdict (CLEAN, WARNING, or TAMPERED). \
        Write a concise, clear 3-4 sentence forensic explanation in \(languageName) covering: \
        1) What the overall verdict and code signature / Gatekeeper status mean for this bundle, \
        2) Any suspicious dylibs, hook symbols, or anomalies detected (or confirm their absence if CLEAN), and \
        3) A practical recommendation for the user. Do not use markdown headings.
        """
    }

    public static func prompt(for report: BundleAuditReport) -> String {
        let suspiciousDylibs = (
            report.bundledLibraries.filter { $0.isTimestampAnomaly || !$0.suspiciousSymbols.isEmpty || !$0.targetStrings.isEmpty }.map(\.name)
            + report.linkedDylibs.filter(\.isSuspicious).map(\.path)
        )
        let hookNames = report.hookCategories.map { "\($0.libraryName) (\($0.symbols.count) symbols)" }
        let criticalFindings = report.findings
            .prefix(8)
            .map { "[\($0.severity.rawValue.uppercased())] \($0.titleKey.rawValue)\($0.detailSuffix)" }

        return """
        Bundle: \(report.bundleName) (\(report.bundleId)) v\(report.shortVersion) (\(report.buildVersion))
        Deterministic Verdict: \(report.verdict.rawValue.uppercased())
        Hardened Runtime: \(report.hasHardenedRuntime ? "Yes" : "No") | Notarized: \(report.isNotarized ? "Yes" : "No")
        Gatekeeper Status: \(report.gatekeeperStatus)
        Authority: \(report.authorities.first ?? "None") | TeamIdentifier: \(report.teamIdentifier)
        Suspicious Dylibs: \(suspiciousDylibs.isEmpty ? "None" : suspiciousDylibs.joined(separator: ", "))
        Hook Symbol Categories: \(hookNames.isEmpty ? "None" : hookNames.joined(separator: ", "))
        Key Findings:
        \(criticalFindings.isEmpty ? "All integrity checks passed cleanly." : criticalFindings.joined(separator: "\n"))
        """
    }

    public static func summarize(
        report: BundleAuditReport,
        languageCode: String,
        model: any SuggestionModel
    ) async -> String? {
        guard model.isAvailable else { return nil }
        guard let raw = try? await model.respond(
            instructions: instructions(for: languageCode),
            prompt: prompt(for: report)
        ) else { return nil }
        let cleaned = LocalModelServer.withoutThinking(raw).trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? nil : cleaned
    }
}

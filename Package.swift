// swift-tools-version: 6.2
// SPDX-License-Identifier: GPL-3.0-only
import PackageDescription

let package = Package(
    name: "Verificator",
    platforms: [.macOS(.v26)],
    targets: [
        // Salt-okunur Mach-O, kod imzası ve dylib enjeksiyonu adli analiz çekirdeği, yerelleştirme, günlük ve güncelleme.
        .target(name: "VerificatorCore"),
        // Test edilebilir SwiftUI uygulama ve durum yönetimi katmanı.
        .target(
            name: "VerificatorKit",
            dependencies: ["VerificatorCore"],
            swiftSettings: [.defaultIsolation(MainActor.self)]
        ),
        // SwiftUI masaüstü uygulaması giriş noktası.
        .executableTarget(
            name: "Verificator",
            dependencies: ["VerificatorKit", "VerificatorCore"],
            swiftSettings: [.defaultIsolation(MainActor.self)]
        ),
        // Otomasyon ve CI iş akışları için komut satırı denetçisi.
        .executableTarget(
            name: "verificator-cli",
            dependencies: ["VerificatorCore"],
            path: "Sources/VerificatorCLI"
        ),
        // Çekirdek, uygulama mantığı ve yerelleştirme doğrulama testleri.
        .testTarget(
            name: "VerificatorTests",
            dependencies: ["VerificatorCore", "VerificatorKit"]
        ),
    ]
)

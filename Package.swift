// swift-tools-version: 6.2
// SPDX-License-Identifier: GPL-3.0-only
import PackageDescription

let package = Package(
    name: "Verificator",
    platforms: [.macOS(.v26)],
    targets: [
        // Salt-okunur Mach-O, kod imzası ve dylib enjeksiyonu adli analiz çekirdeği, yerelleştirme, günlük ve güncelleme.
        .target(name: "VerificatorCore"),
        // SwiftUI arayüzü.
        .executableTarget(
            name: "Verificator",
            dependencies: ["VerificatorCore"],
            swiftSettings: [.defaultIsolation(MainActor.self)]
        ),
        // Çekirdek ve yerelleştirme doğrulama testleri.
        .testTarget(
            name: "VerificatorTests",
            dependencies: ["VerificatorCore"]
        ),
    ]
)

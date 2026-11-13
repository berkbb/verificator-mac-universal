// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing

@Suite("Accessibility Lint Tests")
struct AccessibilityLintTests {

    private var viewsDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/VerificatorKit/Views", isDirectory: true)
    }

    @Test("Every Icon-Only SwiftUI Interactive Control Declares an Accessibility Label")
    func iconOnlyButtonsHaveAccessibilityLabels() throws {
        let fm = FileManager.default
        let files = try fm.contentsOfDirectory(at: viewsDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        #expect(!files.isEmpty)

        var missing: [String] = []
        for fileURL in files {
            let lines = try String(contentsOf: fileURL, encoding: .utf8).components(separatedBy: .newlines)
            for idx in lines.indices {
                let trimmed = lines[idx].trimmingCharacters(in: .whitespaces)
                // Detect single-line or compact icon-only label closures inside Button / SettingsLink / Menu
                guard trimmed.hasPrefix("Image(systemName:") || trimmed == "} label: {" || trimmed.hasPrefix("SettingsLink {") else {
                    continue
                }

                // Look backwards a few lines to verify this Image(systemName:) is a control's direct label closure
                let contextStart = max(0, idx - 5)
                let lookBack = lines[contextStart...idx].joined(separator: "\n")
                let isControlLabel = lookBack.contains("label: {") || lookBack.contains("SettingsLink {")
                guard isControlLabel else { continue }

                let blockEnd = min(lines.count - 1, idx + 12)
                let windowSlice = lines[idx...blockEnd]

                // Find closing brace of the label closure first to see if Text/Label accompanies the Image
                var labelHasText = false
                var foundClosingLabel = false
                for checkIdx in idx...blockEnd {
                    let checkLine = lines[checkIdx]
                    if checkLine.contains("Text(") || checkLine.contains("Label(") {
                        labelHasText = true
                        break
                    }
                    if checkIdx > idx && checkLine.trimmingCharacters(in: .whitespaces).hasPrefix("}") {
                        foundClosingLabel = true
                        break
                    }
                }
                if !foundClosingLabel || labelHasText { continue }

                // For icon-only controls, `.accessibilityLabel(` must appear attached within the modifier chain
                let afterWindow = windowSlice.joined(separator: "\n")
                let hasAccessibility = afterWindow.contains(".accessibilityLabel(")
                if !hasAccessibility && lines[idx].contains("Image(systemName:") {
                    missing.append("\(fileURL.lastPathComponent):\(idx + 1): \(trimmed)")
                }
            }
        }

        #expect(missing.isEmpty, "Icon-only interactive controls missing .accessibilityLabel:\n\(missing.joined(separator: "\n"))")
    }
}

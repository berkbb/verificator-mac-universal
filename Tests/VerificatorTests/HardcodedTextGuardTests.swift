// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing

@Suite("UI Hardcoded Text Guard Tests")
struct HardcodedTextGuardTests {

    private var viewsDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/VerificatorKit/Views", isDirectory: true)
    }

    private func isAllowedLiteral(_ text: String) -> Bool {
        if text.isEmpty { return true }
        if ["codesign -dvvv", "otool -L"].contains(text) { return true }

        // Strip Swift string interpolations like \(...) and inspect remaining static characters
        var stripped = ""
        var index = text.startIndex
        while index < text.endIndex {
            if text[index] == "\\" {
                let next = text.index(after: index)
                if next < text.endIndex && text[next] == "(" {
                    var cursor = text.index(after: next)
                    var depth = 1
                    while cursor < text.endIndex && depth > 0 {
                        if text[cursor] == "(" { depth += 1 }
                        else if text[cursor] == ")" { depth -= 1 }
                        cursor = text.index(after: cursor)
                    }
                    index = cursor
                    continue
                }
            }
            stripped.append(text[index])
            index = text.index(after: index)
        }

        let trimmed = stripped.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return true }
        // Allow pure punctuation / separators / units alongside interpolations (e.g. "12 ms", "•", "→", "/", "+ ")
        let withoutUnits = trimmed
            .replacingOccurrences(of: "ms", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let hasProseLetters = withoutUnits.unicodeScalars.contains { CharacterSet.letters.contains($0) }
        return !hasProseLetters
    }

    @Test("All SwiftUI Views Use Localization Keys Without Hardcoded User-Facing Prose")
    func viewsContainNoHardcodedCopy() throws {
        let fm = FileManager.default
        let files = try fm.contentsOfDirectory(at: viewsDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        #expect(!files.isEmpty)

        // Match Text("..."), Button("..."), Toggle("..."), Section("..."), Picker("..."), TextField("..."), .help("..."), .navigationTitle("...")
        let pattern = #"(?:\b(?:Text|Button|Label|Toggle|Section|Picker|TextField)\s*\(|\.(?:help|navigationTitle|accessibilityLabel)\s*\()\s*"([^"\\]*(?:\\.[^"\\]*)*|\([^)]*\)|[^"]*)"\s*(?:,|\))"#
        let regex = try NSRegularExpression(pattern: pattern)

        var violations: [String] = []
        for fileURL in files {
            let source = try String(contentsOf: fileURL, encoding: .utf8)
            let lines = source.components(separatedBy: .newlines)
            for (lineIndex, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") { continue }
                let ns = line as NSString
                let matches = regex.matches(in: line, range: NSRange(location: 0, length: ns.length))
                for match in matches where match.numberOfRanges >= 2 {
                    let literal = ns.substring(with: match.range(at: 1))
                    if !isAllowedLiteral(literal) {
                        violations.append("\(fileURL.lastPathComponent):\(lineIndex + 1): \"\(literal)\"")
                    }
                }
            }
        }

        #expect(violations.isEmpty, "Found hardcoded UI strings:\n\(violations.joined(separator: "\n"))")
    }
}

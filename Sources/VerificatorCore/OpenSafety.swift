// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Detects and reveals deceptive Unicode characters in bundle, executable, library,
/// process, and persistence names (RTLO overrides, invisible fillers, control scalars).
public enum OpenSafety {
    /// Blank/whitespace-looking Unicode characters historically abused to spoof extensions or filenames.
    private static let blankFillers: Set<UInt32> = [
        0x2800, // Braille pattern blank
        0x3164, // Hangul filler
        0x115F, // Hangul choseong filler
        0x1160, // Hangul jungseong filler
        0xFFA0, // Halfwidth hangul filler
    ]

    /// Emoji presentation / text presentation selectors valid only immediately after an emoji scalar.
    private static let emojiVariationSelectors: Set<UInt32> = [0xFE0E, 0xFE0F]

    /// Standard macOS Finder custom folder icon filename ("Icon\r"). Never flag as malicious masquerading.
    public static let finderCustomIconFileName = "Icon\r"

    /// Returns `true` when `name` contains invisible, bidirectional-override, control, or deceptive Unicode scalars.
    public static func hasDeceptiveCharacters(_ name: String) -> Bool {
        if name == finderCustomIconFileName { return false }
        let scalars = Array(name.unicodeScalars)
        for index in scalars.indices {
            let previous = index > 0 ? scalars[index - 1] : nil
            let next = index + 1 < scalars.count ? scalars[index + 1] : nil
            if isDeceptive(scalars[index], after: previous, before: next) {
                return true
            }
        }
        return false
    }

    /// Replaces hidden, bidirectional, and control scalars with explicit `⟦U+XXXX⟧` markers for safe display.
    public static func visibleName(_ name: String) -> String {
        var result = ""
        result.reserveCapacity(name.count)
        let scalars = Array(name.unicodeScalars)
        for index in scalars.indices {
            let scalar = scalars[index]
            let previous = index > 0 ? scalars[index - 1] : nil
            let next = index + 1 < scalars.count ? scalars[index + 1] : nil
            if isDeceptive(scalar, after: previous, before: next) {
                result += "⟦U+\(String(scalar.value, radix: 16, uppercase: true).leftPadded(toLength: 4, with: "0"))⟧"
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }

    /// Filters a list of candidate names and returns visible-formatted representations of any deceptive entries, deduplicated in order.
    public static func collectDeceptiveNames(in names: [String]) -> [String] {
        var seen: Set<String> = []
        var matches: [String] = []
        for raw in names where hasDeceptiveCharacters(raw) {
            let formatted = visibleName(raw)
            if seen.insert(formatted).inserted {
                matches.append(formatted)
            }
        }
        return matches
    }

    private static func isDeceptive(
        _ scalar: Unicode.Scalar,
        after previous: Unicode.Scalar?,
        before next: Unicode.Scalar?
    ) -> Bool {
        if blankFillers.contains(scalar.value) { return true }
        if emojiVariationSelectors.contains(scalar.value),
           let previous,
           previous.properties.isEmoji {
            return false
        }
        // Allow Zero Width Joiner (U+200D) only when joining genuine emoji sequences.
        if scalar.value == 0x200D,
           let previous, let next,
           (previous.properties.isEmoji || emojiVariationSelectors.contains(previous.value) || (0x1F3FB...0x1F3FF).contains(previous.value)),
           next.properties.isEmoji {
            return false
        }
        switch scalar.properties.generalCategory {
        case .format, .control, .lineSeparator, .paragraphSeparator:
            return true
        default:
            return scalar.properties.isDefaultIgnorableCodePoint
        }
    }
}

private extension String {
    func leftPadded(toLength length: Int, with pad: Character) -> String {
        guard count < length else { return self }
        return String(repeating: pad, count: length - count) + self
    }
}

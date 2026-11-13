// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI

/// Hakkında penceresinin gösterdiği lisans belgeleri. Metin uygulamanın kendi dosyalarından okunur ve
/// uygulama içinde salt okunur gösterilir; düzenlenebilir bir metin düzenleyicide açılmaz.
enum LicenseDocument: String, CaseIterable, Identifiable {
    case app, notices

    var id: String { rawValue }

    var title: LKey {
        switch self {
        case .app: .aboutAppLicense
        case .notices: .aboutNotices
        }
    }

    var subtitle: LKey {
        switch self {
        case .app: .licenseAppSubtitle
        case .notices: .licenseNoticesSubtitle
        }
    }

    var systemImage: String {
        switch self {
        case .app: "doc.text"
        case .notices: "list.bullet.rectangle"
        }
    }

    var publisher: String? {
        switch self {
        case .app: "Babadogan Tech and Edu"
        case .notices: nil
        }
    }

    var licenseName: String? {
        switch self {
        case .app: "GPL-3.0-only"
        case .notices: nil
        }
    }

    func candidates(resources: URL?) -> [URL] {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let bundleParent = Bundle.main.bundleURL.deletingLastPathComponent()
        let bundleGrandparent = bundleParent.deletingLastPathComponent()
        switch self {
        case .app:
            return [
                resources?.appendingPathComponent("Verificator-License.txt"),
                cwd.appendingPathComponent("LICENSE"),
                bundleParent.appendingPathComponent("LICENSE"),
                bundleGrandparent.appendingPathComponent("LICENSE"),
            ].compactMap { $0 }
        case .notices:
            return [
                resources?.appendingPathComponent("Third-Party-Notices.txt"),
                cwd.appendingPathComponent("THIRD_PARTY_NOTICES.md"),
                bundleParent.appendingPathComponent("THIRD_PARTY_NOTICES.md"),
                bundleGrandparent.appendingPathComponent("THIRD_PARTY_NOTICES.md"),
            ].compactMap { $0 }
        }
    }

    func text(resources: URL? = Bundle.main.resourceURL) -> String? {
        for url in candidates(resources: resources) {
            guard let data = try? Data(contentsOf: url), !data.isEmpty else { continue }
            return Self.displayText(data)
        }
        return nil
    }

    static func displayText(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self).replacingOccurrences(of: "\r\n", with: "\n")
    }
}

struct LicenseViewerItem: Identifiable {
    let document: LicenseDocument
    let text: String

    var id: LicenseDocument.ID { document.id }
}

struct LicenseViewerSheet: View {
    let item: LicenseViewerItem
    @Environment(AppSettings.self) private var settings
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: item.document.systemImage)
                    .font(.title2)
                    .foregroundStyle(.tint)

                VStack(alignment: .leading, spacing: 2) {
                    Text(settings.t(item.document.title))
                        .font(.headline)
                    Text(settings.t(item.document.subtitle) + " · " + settings.t(.licenseReadOnly))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()

                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(settings.t(.buttonClose))
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .background(Color(nsColor: .windowBackgroundColor))

            Divider()

            HStack(spacing: 16) {
                if let publisher = item.document.publisher {
                    HStack(spacing: 6) {
                        Image(systemName: "person.badge.shield.checkmark.fill")
                            .foregroundStyle(.tint)
                        Text(settings.t(.licensePublisher) + ":")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        Text(publisher)
                            .font(.caption.bold())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color.accentColor.opacity(0.15))
                            .clipShape(Capsule())
                    }
                }

                if let licenseName = item.document.licenseName {
                    HStack(spacing: 6) {
                        Image(systemName: "lock.shield.fill")
                            .foregroundStyle(.green)
                        Text(settings.t(.licenseLabel) + ":")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        Text(licenseName)
                            .font(.caption.bold())
                    }
                }

                Spacer()

                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(item.text, forType: .string)
                    copied = true
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        copied = false
                    }
                } label: {
                    Label(
                        settings.t(copied ? .licenseCopied : .licenseCopyText),
                        systemImage: copied ? "checkmark" : "doc.on.doc"
                    )
                    .font(.caption)
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.5))

            Divider()

            ScrollView {
                Text(item.text)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color(nsColor: .textColor))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
                    .textSelection(.enabled)
            }
            .background(Color(nsColor: .textBackgroundColor))

            Divider()

            HStack {
                Text(settings.t(.aboutCopyright, AppInfo.currentYear))
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                Spacer()

                Button(settings.t(.buttonClose)) { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(width: 640, height: 540)
    }
}

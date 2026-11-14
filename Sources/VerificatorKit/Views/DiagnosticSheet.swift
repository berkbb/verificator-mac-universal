// SPDX-License-Identifier: GPL-3.0-only
import VerificatorCore
import SwiftUI

struct DiagnosticSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(settings.t(.diagnosticsSheetTitle), systemImage: "stethoscope")
                    .font(.title3.bold())
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                        .font(.title3)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(settings.t(.buttonClose))
            }

            Text(settings.t(.diagnosticsSheetNote))
                .font(.callout)
                .foregroundStyle(.secondary)

            ScrollView {
                Text(model.diagnosticPreviewMarkdown)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .background(Color(NSColor.textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.2)))

            HStack(spacing: 10) {
                if copied {
                    Label(settings.t(.diagnosticsCopiedNotice), systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
                Spacer()
                Button(settings.t(.buttonClose)) {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Button {
                    model.copyDiagnosticReportToClipboard()
                    copied = true
                    Task { @MainActor in
                        try? await Task.sleep(for: .seconds(2))
                        copied = false
                    }
                } label: {
                    Label(settings.t(.diagnosticsCopyButton), systemImage: "doc.on.doc")
                }
                .buttonStyle(.bordered)

                Button {
                    model.saveDiagnosticReportToFile()
                } label: {
                    Label(settings.t(.diagnosticsSaveButton), systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 680, height: 520)
    }
}

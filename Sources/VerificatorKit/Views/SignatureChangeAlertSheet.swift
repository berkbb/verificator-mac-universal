// SPDX-License-Identifier: GPL-3.0-only
import VerificatorCore
import SwiftUI

struct SignatureChangeAlertSheet: View {
    let change: SignatureBaselineChange
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings

    var body: some View {
        let isLost = change.kind == .lostSignature
        let tint: Color = isLost ? .red : .orange
        let icon = isLost ? "xmark.shield.fill" : "exclamationmark.triangle.fill"
        let detailMessage: String = switch change.kind {
        case .signerChanged:
            settings.t(.sigChangeBannerSignerChanged, change.previousSignerDisplay, change.currentSignerDisplay)
        case .lostSignature:
            settings.t(.sigChangeBannerLostSignature, change.previousSignerDisplay)
        case .updatedSameSigner:
            settings.t(.sigChangeBannerSameSignerUpdated, change.currentSignerDisplay)
        }

        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 32))
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 4) {
                    Text(settings.t(.sigChangeModalTitle))
                        .font(.headline)
                    Text(detailMessage)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            VStack(alignment: .leading, spacing: 8) {
                LabeledContent(settings.t(.sigChangeModalPreviousLabel)) {
                    Text(change.previousSignerDisplay)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                LabeledContent(settings.t(.sigChangeModalCurrentLabel)) {
                    Text(change.currentSignerDisplay)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(tint)
                        .textSelection(.enabled)
                }
            }
            .padding(12)
            .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))

            HStack(spacing: 10) {
                Button(settings.t(.sigChangeModalDismissButton)) {
                    model.dismissSignatureChangeModal()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button {
                    model.inspectSignatureChangeModal()
                } label: {
                    Label(settings.t(.sigChangeModalInspectButton), systemImage: "doc.text.magnifyingglass")
                }
                .buttonStyle(.bordered)

                Button {
                    model.acknowledgeSignatureBaselineChange()
                } label: {
                    Label(settings.t(.sigChangeModalTrustButton), systemImage: "checkmark.shield")
                }
                .buttonStyle(.borderedProminent)
                .tint(tint)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI
import UniformTypeIdentifiers

struct DiffView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings

    private var table: StringTable {
        StringTable(bundle: .main)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                headerSection
                endpointSelectors
                actionBar

                if let error = model.diffError {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text(error)
                            .font(.callout)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                }

                if model.isComparingDiff {
                    HStack(spacing: 12) {
                        ProgressView()
                            .controlSize(.small)
                        Text(settings.t(.diffRunning))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
                } else if let diff = model.currentDiff {
                    diffResultsSection(diff)
                }
            }
            .padding(20)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(settings.t(.diffTitle))
                .font(.title2.bold())
            Text(settings.t(.diffEmptyHint))
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var endpointSelectors: some View {
        HStack(alignment: .top, spacing: 12) {
            endpointCard(
                title: settings.t(.diffBaselineHeader),
                url: model.diffBaselineURL,
                endpoint: model.diffBaselineEndpoint,
                forBaseline: true
            )

            Button {
                model.swapDiffEndpoints()
            } label: {
                Image(systemName: "arrow.left.arrow.right")
                    .font(.title3)
                    .padding(8)
            }
            .buttonStyle(.bordered)
            .help(settings.t(.diffSwapSides))
            .accessibilityLabel(settings.t(.diffSwapSides))
            .padding(.top, 36)

            endpointCard(
                title: settings.t(.diffTargetHeader),
                url: model.diffTargetURL,
                endpoint: model.diffTargetEndpoint,
                forBaseline: false
            )
        }
    }

    private func endpointCard(
        title: String,
        url: URL?,
        endpoint: AuditDiffEndpoint?,
        forBaseline: Bool
    ) -> some View {
        GroupBox(label: Text(title).font(.headline)) {
            VStack(alignment: .leading, spacing: 10) {
                if let url {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(OpenSafety.visibleName(endpoint?.report.bundleName ?? url.lastPathComponent))
                            .font(.subheadline.bold())
                        Text(url.path)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                } else {
                    Text(settings.t(.valueNone))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 8) {
                    Button {
                        model.presentDiffFilePanel(forBaseline: forBaseline)
                    } label: {
                        Label(settings.t(.diffChooseFile), systemImage: "doc.badge.plus")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    if model.report != nil {
                        Button(settings.t(.diffUseCurrentReport)) {
                            model.useCurrentReportInDiff(forBaseline: forBaseline)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }

                    let recents = settings.existingRecentBundles
                    if !recents.isEmpty {
                        Menu(settings.t(.diffSelectFromRecent)) {
                            ForEach(recents, id: \.path) { recentURL in
                                Button(recentURL.lastPathComponent) {
                                    model.setDiffFile(recentURL, forBaseline: forBaseline)
                                }
                            }
                        }
                        .controlSize(.small)
                    }
                }
            }
            .padding(.top, 4)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var actionBar: some View {
        HStack(spacing: 10) {
            Button {
                model.runDiffComparison()
            } label: {
                Label(settings.t(.diffRunComparison), systemImage: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.diffBaselineURL == nil || model.diffTargetURL == nil || model.isComparingDiff)

            Button {
                model.exportDiffMarkdown()
            } label: {
                Label(settings.t(.diffExportMarkdown), systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.bordered)
            .disabled(model.currentDiff == nil)

            Spacer()
        }
    }

    @ViewBuilder
    private func diffResultsSection(_ diff: AuditReportDiff) -> some View {
        let hasRegressions = diff.regressionCount > 0
        let hasWarnings = diff.warningCount > 0

        HStack(spacing: 12) {
            Image(systemName: hasRegressions ? "xmark.octagon.fill" : (hasWarnings ? "exclamationmark.triangle.fill" : "checkmark.seal.fill"))
                .font(.title2)
                .foregroundStyle(hasRegressions ? .red : (hasWarnings ? .orange : .green))

            VStack(alignment: .leading, spacing: 2) {
                Text(diff.hasChanges ? settings.t(.diffSummaryChanged) : settings.t(.diffSummaryMatches))
                    .font(.headline)
                Text("\(diff.baseline.report.bundleName) → \(diff.target.report.bundleName)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if diff.regressionCount > 0 {
                Text(settings.t(.diffSummaryRegressions, diff.regressionCount))
                    .font(.caption.bold())
                    .foregroundStyle(.red)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Color.red.opacity(0.14), in: Capsule())
            }
            if diff.warningCount > 0 {
                Text(settings.t(.diffSummaryWarnings, diff.warningCount))
                    .font(.caption.bold())
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Color.orange.opacity(0.14), in: Capsule())
            }
        }
        .padding(14)
        .background((hasRegressions ? Color.red : (hasWarnings ? Color.orange : Color.green)).opacity(0.08), in: RoundedRectangle(cornerRadius: 12))

        GroupBox(label: Label(settings.t(.diffSectionRegressions), systemImage: "shield.lefthalf.filled").font(.headline)) {
            if diff.securityFindings.isEmpty {
                Text(settings.t(.diffNoChangesInSection))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(diff.securityFindings) { finding in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: iconForSeverity(finding.severity))
                                .foregroundStyle(colorForSeverity(finding.severity))
                            Text(finding.formattedMessage(with: table, language: settings.languageCode))
                                .font(.callout)
                                .textSelection(.enabled)
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(colorForSeverity(finding.severity).opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding(.top, 6)
            }
        }

        GroupBox(label: Label(settings.t(.diffSectionMetadata), systemImage: "doc.text.magnifyingglass").font(.headline)) {
            if diff.metadataChanges.isEmpty {
                Text(settings.t(.diffNoChangesInSection))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(diff.metadataChanges) { change in
                        HStack(alignment: .top, spacing: 10) {
                            Text(settings.t(change.fieldKey))
                                .font(.caption.bold())
                                .foregroundStyle(.secondary)
                                .frame(width: 190, alignment: .leading)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("− \(change.localizedBaseline(with: table, language: settings.languageCode))")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.red)
                                    .textSelection(.enabled)
                                Text("+ \(change.localizedTarget(with: table, language: settings.languageCode))")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.green)
                                    .textSelection(.enabled)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Divider()
                    }
                }
                .padding(.top, 6)
            }
        }

        diffSetBox(titleKey: .diffSectionEntitlements, icon: "key.fill", added: diff.addedEntitlements, removed: diff.removedEntitlements)
        diffSetBox(titleKey: .diffSectionRpaths, icon: "folder.badge.gearshape", added: diff.addedRpaths, removed: diff.removedRpaths)
        diffSetBox(titleKey: .diffSectionLinkedDylibs, icon: "link", added: diff.addedLinkedDylibs, removed: diff.removedLinkedDylibs)
        diffSetBox(titleKey: .diffSectionBundledLibraries, icon: "shippingbox", added: diff.addedBundledLibraries, removed: diff.removedBundledLibraries)
        diffSetBox(
            titleKey: .diffSectionHooks,
            icon: "memorychip",
            added: diff.addedHookCategories.map { settings.t($0) },
            removed: diff.removedHookCategories.map { settings.t($0) }
        )
    }

    private func diffSetBox(titleKey: LKey, icon: String, added: [String], removed: [String]) -> some View {
        GroupBox(label: HStack(spacing: 8) {
            Label(settings.t(titleKey), systemImage: icon).font(.headline)
            Spacer()
            if !added.isEmpty {
                Text(settings.t(.diffAddedBadge, added.count))
                    .font(.caption2.bold())
                    .foregroundStyle(.green)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Color.green.opacity(0.14), in: Capsule())
            }
            if !removed.isEmpty {
                Text(settings.t(.diffRemovedBadge, removed.count))
                    .font(.caption2.bold())
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.14), in: Capsule())
            }
        }) {
            if added.isEmpty && removed.isEmpty {
                Text(settings.t(.diffNoChangesInSection))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(added, id: \.self) { item in
                        Text("+ \(item)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.green)
                            .textSelection(.enabled)
                    }
                    ForEach(removed, id: \.self) { item in
                        Text("− \(item)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 6)
            }
        }
    }

    private func iconForSeverity(_ severity: FindingSeverity) -> String {
        switch severity {
        case .critical: return "exclamationmark.octagon.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .info: return "info.circle.fill"
        }
    }

    private func colorForSeverity(_ severity: FindingSeverity) -> Color {
        switch severity {
        case .critical: return .red
        case .warning: return .orange
        case .info: return .blue
        }
    }
}

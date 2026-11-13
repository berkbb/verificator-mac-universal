// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI

private enum RunningProcessFilter: String, CaseIterable, Identifiable {
    case all
    case issues
    case dyldEnv

    var id: String { rawValue }

    var titleKey: LKey {
        switch self {
        case .all: return .filterAll
        case .issues: return .runningFilterIssues
        case .dyldEnv: return .runningFilterDyldEnv
        }
    }
}

private enum PersistenceFilter: String, CaseIterable, Identifiable {
    case all
    case issues
    case missing

    var id: String { rawValue }

    var titleKey: LKey {
        switch self {
        case .all: return .filterAll
        case .issues: return .persistenceFilterIssues
        case .missing: return .persistenceFilterMissing
        }
    }
}

struct RunningProcessesAuditView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @State private var searchText = ""
    @State private var filter: RunningProcessFilter = .all

    var body: some View {
        VStack(spacing: 0) {
            if model.isScanningRunning {
                scanningView
            } else if let summary = model.runningSummary {
                resultsView(summary)
            } else {
                emptyView
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "cpu")
                .font(.system(size: 52))
                .foregroundStyle(.blue)
            Text(settings.t(.runningTitle))
                .font(.title2.bold())
            Text(settings.t(.runningEmptyHint))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 580)
            Button {
                model.startRunningProcessesScan()
            } label: {
                Label(settings.t(.runningScanButton), systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .padding(32)
    }

    private var scanningView: some View {
        VStack(spacing: 14) {
            let total = max(1, model.runningProgress.total)
            ProgressView(value: Double(model.runningProgress.current), total: Double(total))
                .frame(maxWidth: 360)
            Text(settings.t(.runningScanningProgress, model.runningProgress.current, model.runningProgress.total))
                .font(.headline)
            if !model.runningProgress.name.isEmpty {
                Text(model.runningProgress.name)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Button(role: .cancel) {
                model.cancelRunningProcessesScan()
            } label: {
                Label(settings.t(.actionCancelScan), systemImage: "xmark.circle")
            }
            .buttonStyle(.bordered)
        }
        .padding(32)
    }

    @ViewBuilder
    private func resultsView(_ summary: RunningProcessesAuditSummary) -> some View {
        let filtered = filteredItems(from: summary)

        VStack(spacing: 0) {
            HStack(spacing: 10) {
                TextField(settings.t(.runningSearchPlaceholder), text: $searchText)
                    .textFieldStyle(.roundedBorder)

                Picker("", selection: $filter) {
                    ForEach(RunningProcessFilter.allCases) { item in
                        Text(settings.t(item.titleKey)).tag(item)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 180)

                Button {
                    model.startRunningProcessesScan()
                } label: {
                    Label(settings.t(.runningRescanButton), systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            HStack {
                Text(
                    settings.t(
                        .runningSummaryStats,
                        summary.totalCount,
                        summary.cleanCount,
                        summary.warningCount,
                        summary.tamperedCount,
                        summary.uniqueBinariesCount
                    )
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 8)

            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(filtered) { proc in
                        processCard(proc)
                    }
                }
                .padding(16)
            }
        }
    }

    private func filteredItems(from summary: RunningProcessesAuditSummary) -> [RunningProcessItem] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return summary.items.filter { item in
            switch filter {
            case .all:
                break
            case .issues:
                if item.verdict == .clean && item.dyldInsertLibraries.isEmpty { return false }
            case .dyldEnv:
                if item.dyldInsertLibraries.isEmpty { return false }
            }

            if query.isEmpty { return true }
            return item.name.localizedCaseInsensitiveContains(query)
                || "\(item.pid)".contains(query)
                || item.executablePath.localizedCaseInsensitiveContains(query)
                || item.teamIdentifier.localizedCaseInsensitiveContains(query)
        }
    }

    private func processCard(_ proc: RunningProcessItem) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VerdictBadgeIcon(verdict: proc.verdict)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(OpenSafety.visibleName(proc.name))
                        .font(.subheadline.bold())
                    Text(settings.t(.runningColPid, Int(proc.pid)))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())

                    if let parentName = proc.parentName, let parentPid = proc.parentPid {
                        Text(settings.t(.runningParentProcessLabel, parentName, Int(parentPid)))
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }

                    if proc.teamIdentifier != "not set" {
                        Text(proc.teamIdentifier)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }

                    if proc.isQuarantined {
                        TagCapsule(text: settings.t(.valueQuarantined), color: .orange)
                    }

                    if proc.dynamicSignatureMismatch {
                        TagCapsule(text: settings.t(.runningDynamicSigMismatchTitle), color: .red)
                    }

                    if !proc.unsignedMappedLibraries.isEmpty {
                        TagCapsule(text: settings.t(.runningUnsignedMappedLibTitle), color: .orange)
                    }

                    if !proc.envReadable {
                        TagCapsule(text: settings.t(.runningEnvUnreadable), color: .secondary)
                    }
                }

                Text(proc.executablePath)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)

                if !proc.dyldInsertLibraries.isEmpty {
                    Text(settings.t(.runningDyldEnvDetected, proc.dyldInsertLibraries.joined(separator: ":")))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }

                if !proc.unsignedMappedLibraries.isEmpty {
                    Text(settings.t(.runningUnsignedMappedLibDesc) + proc.unsignedMappedLibraries.joined(separator: ", "))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }

                if !proc.authorities.isEmpty {
                    Text(proc.authorities.joined(separator: " → "))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button {
                model.inspectSystemAuditTarget(at: proc.inspectionTargetPath)
            } label: {
                Label(settings.t(.runningOpenInInspector), systemImage: "magnifyingglass")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(10)
        .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
    }
}

struct PersistenceAuditView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @State private var searchText = ""
    @State private var filter: PersistenceFilter = .all

    var body: some View {
        VStack(spacing: 0) {
            if model.isScanningPersistence {
                scanningView
            } else if let summary = model.persistenceSummary {
                resultsView(summary)
            } else {
                emptyView
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            model.refreshSystemSecurityStatus()
        }
    }

    @ViewBuilder
    private var fdaBanner: some View {
        if !model.isFullDiskAccessGranted {
            HStack(spacing: 10) {
                Image(systemName: "lock.trianglebadge.exclamationmark")
                    .foregroundStyle(.orange)
                Text(settings.t(.fdaPersistenceHint))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button(settings.t(.fdaOpenSettings)) {
                    FullDiskAccess.openSystemSettings()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            .padding(10)
            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checklist")
                .font(.system(size: 52))
                .foregroundStyle(.blue)
            Text(settings.t(.persistenceTitle))
                .font(.title2.bold())
            Text(settings.t(.persistenceEmptyHint))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 580)
            fdaBanner
                .frame(maxWidth: 580)
            Button {
                model.startPersistenceScan()
            } label: {
                Label(settings.t(.persistenceScanButton), systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .padding(32)
    }

    private var scanningView: some View {
        VStack(spacing: 14) {
            let total = max(1, model.persistenceProgress.total)
            ProgressView(value: Double(model.persistenceProgress.current), total: Double(total))
                .frame(maxWidth: 360)
            Text(settings.t(.persistenceScanningProgress, model.persistenceProgress.current, model.persistenceProgress.total))
                .font(.headline)
            if !model.persistenceProgress.name.isEmpty {
                Text(model.persistenceProgress.name)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Button(role: .cancel) {
                model.cancelPersistenceScan()
            } label: {
                Label(settings.t(.actionCancelScan), systemImage: "xmark.circle")
            }
            .buttonStyle(.bordered)
        }
        .padding(32)
    }

    @ViewBuilder
    private func resultsView(_ summary: PersistenceAuditSummary) -> some View {
        let filtered = filteredItems(from: summary)

        VStack(spacing: 0) {
            HStack(spacing: 10) {
                TextField(settings.t(.persistenceSearchPlaceholder), text: $searchText)
                    .textFieldStyle(.roundedBorder)

                Picker("", selection: $filter) {
                    ForEach(PersistenceFilter.allCases) { item in
                        Text(settings.t(item.titleKey)).tag(item)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 180)

                Button {
                    model.startPersistenceScan()
                } label: {
                    Label(settings.t(.persistenceRescanButton), systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            HStack {
                Text(
                    settings.t(
                        .persistenceSummaryStats,
                        summary.totalCount,
                        summary.cleanCount,
                        summary.warningCount,
                        summary.tamperedCount,
                        summary.missingExecutableCount
                    )
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 8)

            Divider()

            if !model.isFullDiskAccessGranted {
                fdaBanner
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(filtered) { item in
                        persistenceCard(item)
                    }
                }
                .padding(16)
            }
        }
    }

    private func filteredItems(from summary: PersistenceAuditSummary) -> [PersistenceAuditItem] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return summary.items.filter { item in
            switch filter {
            case .all:
                break
            case .issues:
                if item.verdict == .clean { return false }
            case .missing:
                if item.executableExists { return false }
            }

            if query.isEmpty { return true }
            return item.label.localizedCaseInsensitiveContains(query)
                || (item.programPath?.localizedCaseInsensitiveContains(query) ?? false)
                || (item.plistPath?.localizedCaseInsensitiveContains(query) ?? false)
                || item.teamIdentifier.localizedCaseInsensitiveContains(query)
        }
    }

    private func persistenceCard(_ item: PersistenceAuditItem) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VerdictBadgeIcon(verdict: item.verdict)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(OpenSafety.visibleName(item.label))
                        .font(.subheadline.bold())

                    TagCapsule(text: settings.t(item.scope.labelKey), color: .blue)

                    if item.teamIdentifier != "not set" {
                        Text(item.teamIdentifier)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    if item.runAtLoad {
                        TagCapsule(text: settings.t(.persistenceRunAtLoadBadge), color: .secondary)
                    }
                    if item.isDisabled {
                        TagCapsule(text: settings.t(.persistenceDisabledBadge), color: .secondary)
                    }
                    if item.hasDyldInsertEnv {
                        TagCapsule(text: settings.t(.persistencePlistDyldEnv), color: .red)
                    }
                    if item.isQuarantined {
                        TagCapsule(text: settings.t(.valueQuarantined), color: .orange)
                    }
                }

                if let programPath = item.programPath {
                    if !item.executableExists {
                        Text(settings.t(.persistenceExecutableMissing, programPath))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                    } else {
                        Text(programPath)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                } else {
                    Text(settings.t(.runningBinaryMissing))
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                if let dyld = item.dyldInsertValue {
                    Text(settings.t(.runningDyldEnvDetected, dyld))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.red)
                }

                if !item.authorities.isEmpty {
                    Text(item.authorities.joined(separator: " → "))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 6) {
                if let programPath = item.programPath, item.executableExists, item.isMachO {
                    let inspectTarget = SystemAudit.enclosingAppBundlePath(forExecutablePath: programPath) ?? programPath
                    Button {
                        model.inspectSystemAuditTarget(at: inspectTarget)
                    } label: {
                        Label(settings.t(.runningOpenInInspector), systemImage: "magnifyingglass")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }

                if let plistPath = item.plistPath {
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: plistPath)])
                    } label: {
                        Label(settings.t(.persistenceRevealPlist), systemImage: "folder")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct VerdictBadgeIcon: View {
    let verdict: IntegrityVerdict

    var body: some View {
        Image(systemName: iconName)
            .font(.title3)
            .foregroundStyle(color)
            .padding(.top, 2)
    }

    private var iconName: String {
        switch verdict {
        case .clean: return "checkmark.seal.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .tampered: return "xmark.octagon.fill"
        }
    }

    private var color: Color {
        switch verdict {
        case .clean: return .green
        case .warning: return .orange
        case .tampered: return .red
        }
    }
}

struct TagCapsule: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.bold())
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(color.opacity(0.14), in: Capsule())
    }
}

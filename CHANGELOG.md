# Changelog

This file follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] — 2026-11-10

### Added

- **Master–Detail Interface (`NavigationSplitView`):** Sidebar navigation with **Forensic Audit** sections (**Home**, **Overview & Signature** `⌘1`, **Mach-O & Dylib Analysis** `⌘2`, **Memory & Hook Symbols** `⌘3`, **Raw Forensic Output** `⌘4`) and **Recent Bundles** displaying native application icons, active bundle indicator, and context menus (**Refresh**, **Show in Finder**, **Remove from List**, **Clear Recent Bundles**).
- **Refresh (`⌘R`) and Clear (`⇧⌘W`) Controls:** Prominent **Refresh** and **Clear** buttons in the header bar, verdict banner, and the **File** / **Audit** menus (`⌘R` and `⇧⌘W`).
- **4-Tab Settings Window (`⌘,`):**
  - **General:** Language picker (`Turkish`, `English`, `Romanian`, `System`) with mandatory macOS menu bar & system dialog restart notice, and Appearance picker (`System`, `Light`, `Dark`).
  - **Scan:** Toggles for deep framework signature verification (`Contents/Frameworks`), target string extraction, automatic scan on drag-and-drop, and revealing exported Markdown reports in Finder.
  - **Shortcuts:** Interactive keyboard shortcut recorder with modifier validation, conflict detection, per-action reset, and reset-all support.
  - **Forensic Engine & Updates:** Live availability check for `/usr/bin/codesign`, `/usr/sbin/spctl`, `/usr/bin/otool`, `/usr/bin/nm`, and `/usr/bin/strings`, plus GitHub Releases update checking.
- **About Window & Read-Only License Viewer:** Displays app version/build, forensic engine credits, Website/Repository links, and an in-app read-only sheet (`LicenseViewerSheet`) for `GPL-3.0-only` and `THIRD_PARTY_NOTICES.md`.
- **Console-Style Log Window (`⌥⌘L`):** Lists forensic scans, signature checks, and update checks with **All Messages** / **Errors & Warnings** filtering, search, detail pane, Copy, Clear, Show in Finder, and Open in Console (`~/Library/Logs/Verificator/Verificator.log`).
- **Ed25519 Release Signing & Packaging (`dist/`):** `Scripts/update_signing.swift`, `Scripts/package.sh`, `Scripts/release.sh`, `Paketle.command`, and `Yayimla.command` build universal (`arm64` + `x86_64`) bundles under `build/` and `.dmg`, `.dmg.sig`, and `SHA256SUMS.txt` under `dist/`.
- **Agent Governance (`.agents/`) & Graphify Knowledge Graph:** Full English `.agents/` hierarchy (`AGENTS.md`, `context/`, `rules/`, `skills/`) and offline AST graph (`graphify-out/`).

// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation

/// Surface abstraction for `NSDockTile` so Dock progress rendering can be unit-tested cleanly.
@MainActor
public protocol DockTileSurface: AnyObject {
    var size: NSSize { get }
    var badgeLabel: String? { get set }
    var contentView: NSView? { get set }
    func display()
}

extension NSDockTile: DockTileSurface {}

/// Value state rendered on the Dock icon tile during batch folder scans.
public struct DockTileState: Equatable, Sendable {
    public var showsBar: Bool
    public var percent: Int?

    public init(showsBar: Bool = false, percent: Int? = nil) {
        self.showsBar = showsBar
        self.percent = percent
    }

    public var isEmpty: Bool { !showsBar }
}

/// Renders a crisp progress bar overlay in the lower portion of the macOS Dock icon during batch scans.
@MainActor
public final class DockProgress {
    private let injectedTile: (any DockTileSurface)?
    private var tileView: DockTileView?
    public private(set) var lastState: DockTileState?

    public init(tile: (any DockTileSurface)? = nil) {
        self.injectedTile = tile
    }

    public func update(fraction: Double?, active: Bool, enabled: Bool = true) {
        let tile: (any DockTileSurface)? = injectedTile ?? NSApp?.dockTile
        guard let tile else { return }
        let clampedPercent = active
            ? fraction.map { min(100, max(0, Int(($0 * 100).rounded()))) }
            : nil
        let state = enabled ? DockTileState(showsBar: active, percent: clampedPercent) : DockTileState()
        if state == lastState { return }
        lastState = state
        tile.badgeLabel = nil
        if state.isEmpty {
            tile.contentView = nil
        } else {
            let view = tileView ?? DockTileView(frame: NSRect(origin: .zero, size: tile.size))
            tileView = view
            view.state = state
            tile.contentView = view
        }
        tile.display()
    }
}

/// Custom `NSView` drawing the application icon and a high-contrast progress bar in the bottom third.
@MainActor
public final class DockTileView: NSView {
    public var state = DockTileState() { didSet { needsDisplay = true } }

    public override func draw(_ dirtyRect: NSRect) {
        let unit = max(bounds.width / 128, 0.25)
        NSApp?.applicationIconImage.draw(in: bounds)
        guard state.showsBar else { return }
        drawBar(NSRect(x: 8 * unit, y: 8 * unit, width: 112 * unit, height: 22 * unit))
    }

    static let fillStart = NSColor(srgbRed: 0.20, green: 0.90, blue: 0.40, alpha: 1)
    static let fillEnd = NSColor(srgbRed: 0.65, green: 1.00, blue: 0.40, alpha: 1)

    private func drawBar(_ frame: NSRect) {
        let radius = frame.height / 2
        let track = NSBezierPath(roundedRect: frame, xRadius: radius, yRadius: radius)
        NSColor.black.withAlphaComponent(0.75).setFill()
        track.fill()
        NSColor.white.setStroke()
        track.lineWidth = max(1, frame.height / 10)
        track.stroke()

        let inner = frame.insetBy(dx: frame.height * 0.18, dy: frame.height * 0.18)
        let fraction = state.percent.map { min(1, max(0, Double($0) / 100)) }
        var fill = inner
        fill.size.width = fraction.map { max(inner.height, inner.width * $0) } ?? inner.width
        let fillPath = NSBezierPath(roundedRect: fill, xRadius: inner.height / 2, yRadius: inner.height / 2)
        let alpha: CGFloat = fraction == nil ? 0.45 : 1.0
        NSGradient(
            starting: Self.fillStart.withAlphaComponent(alpha),
            ending: Self.fillEnd.withAlphaComponent(alpha)
        )?.draw(in: fillPath, angle: 0)
    }
}

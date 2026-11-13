// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Testing
@testable import VerificatorKit

@MainActor
private final class FakeDockTile: DockTileSurface {
    let size = NSSize(width: 128, height: 128)
    var badgeLabel: String?
    var contentView: NSView?
    var displays = 0
    func display() { displays += 1 }
}

@Suite("Dock Progress Overlay Tests")
@MainActor
struct DockProgressTests {
    @Test("Shows progress bar while active and clears when idle")
    func showsBarWhileActiveAndClearsWhenIdle() throws {
        let tile = FakeDockTile()
        let dock = DockProgress(tile: tile)

        dock.update(fraction: nil, active: false, enabled: true)
        #expect(tile.badgeLabel == nil && tile.contentView == nil)

        dock.update(fraction: 0.42, active: true, enabled: true)
        #expect(tile.badgeLabel == nil)
        let view = try #require(tile.contentView as? DockTileView)
        #expect(view.state == DockTileState(showsBar: true, percent: 42))

        dock.update(fraction: 1.0, active: false, enabled: true)
        #expect(tile.badgeLabel == nil && tile.contentView == nil)
    }

    @Test("Disabled DockProgress renders nothing")
    func disabledShowsNothing() {
        let tile = FakeDockTile()
        DockProgress(tile: tile).update(fraction: 0.5, active: true, enabled: false)
        #expect(tile.badgeLabel == nil && tile.contentView == nil)
    }

    @Test("Redraws only when visible state changes")
    func redrawsOnlyOnStateChange() {
        let tile = FakeDockTile()
        let dock = DockProgress(tile: tile)
        for _ in 0..<5 {
            dock.update(fraction: 0.25, active: true, enabled: true)
        }
        #expect(tile.displays == 1)
        dock.update(fraction: 0.26, active: true, enabled: true)
        #expect(tile.displays == 2)
    }

    @Test("Draws bright green progress fill at the bottom of the tile")
    func drawsBrightGreenProgressBar() throws {
        func render(_ state: DockTileState) throws -> NSBitmapImageRep {
            let view = DockTileView(frame: NSRect(x: 0, y: 0, width: 128, height: 128))
            view.state = state
            let rep = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
            view.cacheDisplay(in: view.bounds, to: rep)
            return rep
        }
        func isBrightGreen(_ color: NSColor?) -> Bool {
            guard let srgb = color?.usingColorSpace(.sRGB) else { return false }
            return srgb.greenComponent > 0.8 && srgb.redComponent < 0.8 && srgb.blueComponent < 0.6
        }

        let empty = try render(DockTileState(showsBar: true, percent: 0))
        let scale = CGFloat(empty.pixelsWide) / 128
        let barY = Int(109 * scale)
        #expect(isBrightGreen(empty.colorAt(x: Int(18 * scale), y: barY)))
        #expect(!isBrightGreen(empty.colorAt(x: Int(100 * scale), y: barY)))

        let half = try render(DockTileState(showsBar: true, percent: 50))
        #expect(isBrightGreen(half.colorAt(x: Int(50 * scale), y: barY)))
        #expect(!isBrightGreen(half.colorAt(x: Int(100 * scale), y: barY)))
    }
}

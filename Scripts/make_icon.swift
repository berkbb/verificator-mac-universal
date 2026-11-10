// SPDX-License-Identifier: GPL-3.0-only
// Verificator'ın uygulama simgesini (Resources/AppIcon.icns) sıfırdan çizer.
// macOS squircle üzerinde koyu zümrüt/siber-adli kalkan + büyüteç + ikili kod mührü.

import AppKit

let root = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? FileManager.default.currentDirectoryPath)
let resources = root.appendingPathComponent("Resources", isDirectory: true)
try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)

func renderIcon(size: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    )!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(size)

    // macOS Big Sur+ squircle oranı: 1024'te 100px dış boşluk, 824px gövde, ~185px köşe yarıçapı.
    let pad = s * 0.09765625
    let body = NSRect(x: pad, y: pad, width: s - pad * 2, height: s - pad * 2)
    let radius = body.width * 0.225
    let squircle = NSBezierPath(roundedRect: body, xRadius: radius, yRadius: radius)

    // Derin siber-adli lacivert-zümrüt arka plan.
    NSGraphicsContext.current?.saveGraphicsState()
    let dropShadow = NSShadow()
    dropShadow.shadowOffset = NSSize(width: 0, height: -s * 0.02)
    dropShadow.shadowBlurRadius = s * 0.045
    dropShadow.shadowColor = NSColor(calibratedWhite: 0, alpha: 0.42)
    dropShadow.set()
    NSColor(calibratedRed: 0.05, green: 0.09, blue: 0.16, alpha: 1).setFill()
    squircle.fill()
    NSGraphicsContext.current?.restoreGraphicsState()

    NSGradient(colors: [
        NSColor(calibratedRed: 0.06, green: 0.18, blue: 0.28, alpha: 1),
        NSColor(calibratedRed: 0.04, green: 0.11, blue: 0.20, alpha: 1),
        NSColor(calibratedRed: 0.02, green: 0.07, blue: 0.14, alpha: 1),
    ])!.draw(in: squircle, angle: -90)

    NSGraphicsContext.current?.saveGraphicsState()
    squircle.addClip()

    // Üst parıltı ve kalkan halesi.
    let glowRect = NSRect(x: body.minX - body.width * 0.1, y: body.midY, width: body.width * 1.2, height: body.height * 0.75)
    NSGradient(colors: [
        NSColor(calibratedRed: 0.12, green: 0.82, blue: 0.65, alpha: 0.26),
        NSColor(calibratedRed: 0.12, green: 0.82, blue: 0.65, alpha: 0.0),
    ])!.draw(in: NSBezierPath(ovalIn: glowRect), relativeCenterPosition: .zero)

    // Merkezde adli kalkan (Shield).
    let cx = s * 0.50
    let shieldTop = s * 0.77
    let shieldBottom = s * 0.22
    let shieldHalfW = s * 0.235

    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: cx, y: shieldTop))
    shield.line(to: NSPoint(x: cx + shieldHalfW, y: shieldTop - s * 0.08))
    shield.curve(
        to: NSPoint(x: cx, y: shieldBottom),
        controlPoint1: NSPoint(x: cx + shieldHalfW, y: s * 0.40),
        controlPoint2: NSPoint(x: cx + shieldHalfW * 0.55, y: shieldBottom + s * 0.06)
    )
    shield.curve(
        to: NSPoint(x: cx - shieldHalfW, y: shieldTop - s * 0.08),
        controlPoint1: NSPoint(x: cx - shieldHalfW * 0.55, y: shieldBottom + s * 0.06),
        controlPoint2: NSPoint(x: cx - shieldHalfW, y: s * 0.40)
    )
    shield.close()

    NSGradient(colors: [
        NSColor(calibratedRed: 0.12, green: 0.78, blue: 0.60, alpha: 0.96),
        NSColor(calibratedRed: 0.06, green: 0.52, blue: 0.46, alpha: 0.96),
        NSColor(calibratedRed: 0.04, green: 0.36, blue: 0.38, alpha: 0.98),
    ])!.draw(in: shield, angle: -90)

    NSColor(calibratedWhite: 1.0, alpha: 0.35).setStroke()
    shield.lineWidth = max(1.5, s * 0.012)
    shield.stroke()

    // Kalkan içinde Mach-O / İkili doğrulama çizgileri.
    let barColor = NSColor(calibratedWhite: 1.0, alpha: 0.26)
    barColor.setFill()
    for i in 0..<3 {
        let y = s * (0.60 - CGFloat(i) * 0.065)
        let w = s * (i == 1 ? 0.22 : 0.28)
        let bar = NSBezierPath(roundedRect: NSRect(x: cx - w / 2, y: y, width: w, height: s * 0.022), xRadius: s * 0.01, yRadius: s * 0.01)
        bar.fill()
    }

    // Kalkan ortasında onay işareti (Checkmark).
    let check = NSBezierPath()
    check.move(to: NSPoint(x: cx - s * 0.085, y: s * 0.43))
    check.line(to: NSPoint(x: cx - s * 0.02, y: s * 0.365))
    check.line(to: NSPoint(x: cx + s * 0.10, y: s * 0.495))
    check.lineCapStyle = .round
    check.lineJoinStyle = .round
    check.lineWidth = max(2.0, s * 0.038)
    NSColor.white.setStroke()
    check.stroke()

    // Sağ alt köşede büyüteç halkası (Forensic Magnifier).
    let lensCenter = NSPoint(x: s * 0.64, y: s * 0.34)
    let lensRadius = s * 0.105
    let handleEnd = NSPoint(x: s * 0.76, y: s * 0.22)

    let handle = NSBezierPath()
    handle.move(to: NSPoint(x: lensCenter.x + lensRadius * 0.68, y: lensCenter.y - lensRadius * 0.68))
    handle.line(to: handleEnd)
    handle.lineCapStyle = .round
    handle.lineWidth = max(2.0, s * 0.042)
    NSColor(calibratedRed: 0.90, green: 0.95, blue: 1.0, alpha: 0.95).setStroke()
    handle.stroke()

    let lensRect = NSRect(x: lensCenter.x - lensRadius, y: lensCenter.y - lensRadius, width: lensRadius * 2, height: lensRadius * 2)
    let lensPath = NSBezierPath(ovalIn: lensRect)
    NSColor(calibratedRed: 0.05, green: 0.16, blue: 0.26, alpha: 0.88).setFill()
    lensPath.fill()
    NSColor(calibratedRed: 0.92, green: 0.97, blue: 1.0, alpha: 0.96).setStroke()
    lensPath.lineWidth = max(1.5, s * 0.026)
    lensPath.stroke()

    NSGraphicsContext.current?.restoreGraphicsState()

    // İnce dış çerçeve.
    NSColor(calibratedWhite: 1, alpha: 0.18).setStroke()
    squircle.lineWidth = max(1, s * 0.004)
    squircle.stroke()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

func makeICNS(into destination: URL) throws {
    let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("Verificator-\(UUID().uuidString).iconset", isDirectory: true)
    try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: iconset) }

    let slots: [(String, Int)] = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024),
    ]
    var cache: [Int: Data] = [:]
    for (name, pixels) in slots {
        let data = cache[pixels] ?? renderIcon(size: pixels)
        cache[pixels] = data
        try data.write(to: iconset.appendingPathComponent(name))
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    process.arguments = ["-c", "icns", iconset.path, "-o", destination.path]
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw NSError(domain: "make_icon", code: Int(process.terminationStatus))
    }
}

try makeICNS(into: resources.appendingPathComponent("AppIcon.icns"))
print("Generated AppIcon.icns")

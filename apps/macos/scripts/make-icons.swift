#!/usr/bin/env swift
// Draws Keystead's icons into the app's asset catalog:
//
//   AppIcon / AppIcon-Dev          the app icon for Release and Debug builds
//   MenuBarIcon / MenuBarIcon-Dev  the menu bar template images
//
// The mark is a key ring: three keys on one ring, a team's keys kept in one place. Release
// is teal; Dev is orange with a DEV bar along the bottom, and its menu bar icon carries a
// dot, so the two builds are easy to tell apart.
//
// Usage (from apps/macos):  swift scripts/make-icons.swift [preview.png]

import AppKit
import ImageIO

let appDirectory = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
let assets = appDirectory.appending(path: "Keystead/Assets.xcassets")

enum Variant: CaseIterable {
    case release, dev

    var appIconName: String { self == .release ? "AppIcon" : "AppIcon-Dev" }
    var menuBarName: String { self == .release ? "MenuBarIcon" : "MenuBarIcon-Dev" }
    /// The tile's gradient, top to bottom.
    var top: CGColor { self == .release ? rgb(0x2FA894) : rgb(0xF7A546) }
    var bottom: CGColor { self == .release ? rgb(0x0D524E) : rgb(0xD95F18) }
    /// The keys are white at the top, shading slightly towards the tile's colour.
    var markShade: CGColor { self == .release ? rgb(0xDCE9E6) : rgb(0xF7E4D6) }
}

let sRGB = CGColorSpace(name: CGColorSpace.sRGB)!

func rgb(_ hex: UInt32, alpha: CGFloat = 1) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
        green: CGFloat((hex >> 8) & 0xFF) / 255,
        blue: CGFloat(hex & 0xFF) / 255,
        alpha: alpha)
}

// MARK: - The mark, in a 100-unit box with y pointing up

/// One piece of the mark: shapes to fill, then holes to cut out of them.
struct Piece {
    var shapes: [CGPath]
    var holes: [CGPath] = []

    func applying(_ transform: CGAffineTransform) -> Piece {
        var transform = transform
        return Piece(
            shapes: shapes.map { $0.copy(using: &transform)! },
            holes: holes.map { $0.copy(using: &transform)! })
    }
}

func circle(radius: CGFloat) -> CGPath {
    CGPath(ellipseIn: CGRect(x: -radius, y: -radius, width: 2 * radius, height: 2 * radius), transform: nil)
}

/// A key pointing right with its bow at the origin. Its shapes are filled one by one: filled
/// as one path, overlapping shapes can cancel out and leave notches.
func key() -> Piece {
    let length: CGFloat = 40, thickness: CGFloat = 7.5, start: CGFloat = 6
    return Piece(
        shapes: [
            circle(radius: 10.25),
            // The shaft, then the two teeth.
            CGPath(
                roundedRect: CGRect(x: start, y: -thickness / 2, width: length, height: thickness),
                cornerWidth: 2, cornerHeight: 2, transform: nil),
            CGPath(
                roundedRect: CGRect(x: start + length - 15, y: 0, width: 6, height: thickness / 2 + 7),
                cornerWidth: 1.5, cornerHeight: 1.5, transform: nil),
            CGPath(
                roundedRect: CGRect(x: start + length - 6, y: 0, width: 6, height: thickness / 2 + 4.5),
                cornerWidth: 1.5, cornerHeight: 1.5, transform: nil),
        ],
        holes: [circle(radius: 3.75)])
}

/// The key ring as pieces in drawing order: the ring, then the left, right and middle keys
/// hanging from it. It is centred on its own outline, so the space around it is even.
func keyRing() -> [Piece] {
    var pieces = [
        Piece(shapes: [
            CGPath(ellipseIn: CGRect(x: 37, y: 69, width: 26, height: 26), transform: nil)
                .copy(strokingWithWidth: 7.5, lineCap: .round, lineJoin: .round, miterLimit: 10)
        ])
    ]
    for angle in [-0.5, 0.5, 0] as [CGFloat] {
        pieces.append(
            key().applying(
                CGAffineTransform(translationX: 50, y: 82)
                    .rotated(by: -.pi / 2 + angle)
                    .translatedBy(x: 19, y: 0)))
    }
    let outline = bounds(pieces)
    return pieces.map { $0.applying(CGAffineTransform(translationX: 50 - outline.midX, y: 50 - outline.midY)) }
}

func bounds(_ pieces: [Piece]) -> CGRect {
    pieces.flatMap(\.shapes).reduce(CGRect.null) { $0.union($1.boundingBoxOfPath) }
}

let mark = keyRing()

/// Fills the mark through `transform`. Each piece is drawn over the earlier ones with a thin
/// gap cut around it, so the keys read as hanging on the ring instead of merging into it.
/// With `shade`, the mark fades from `color` at the top to `shade` at the bottom.
func drawMark(in context: CGContext, transform: CGAffineTransform, color: CGColor, shade: CGColor? = nil) {
    context.saveGState()
    context.beginTransparencyLayer(auxiliaryInfo: nil)
    context.concatenate(transform)
    context.setFillColor(color)
    for piece in mark {
        context.setBlendMode(.clear)
        for shape in piece.shapes {
            context.addPath(shape.copy(strokingWithWidth: 3.2, lineCap: .round, lineJoin: .round, miterLimit: 10))
            context.fillPath()
        }
        context.setBlendMode(.normal)
        for shape in piece.shapes {
            context.addPath(shape)
            context.fillPath()
        }
        context.setBlendMode(.clear)
        for hole in piece.holes {
            context.addPath(hole)
            context.fillPath()
        }
    }
    if let shade {
        context.setBlendMode(.sourceAtop)
        let gradient = CGGradient(colorsSpace: sRGB, colors: [color, shade] as CFArray, locations: [0, 1])!
        context.drawLinearGradient(gradient, start: CGPoint(x: 50, y: 100), end: CGPoint(x: 50, y: 0), options: [])
    }
    context.endTransparencyLayer()
    context.restoreGState()
}

// MARK: - App icon (1024 design grid, Apple's 824-point tile)

func drawAppIcon(_ variant: Variant, in context: CGContext, pixels: Int) {
    let scale = CGFloat(pixels) / 1024
    context.scaleBy(x: scale, y: scale)
    let tile = CGPath(
        roundedRect: CGRect(x: 100, y: 100, width: 824, height: 824),
        cornerWidth: 185.4, cornerHeight: 185.4, transform: nil)

    // Shadow offsets and blurs are in pixels, not affected by the scale.
    context.saveGState()
    context.setShadow(
        offset: CGSize(width: 0, height: -10 * scale), blur: 22 * scale, color: rgb(0x000000, alpha: 0.3))
    context.setFillColor(variant.bottom)
    context.addPath(tile)
    context.fillPath()
    context.restoreGState()

    context.saveGState()
    context.addPath(tile)
    context.clip()
    let gradient = CGGradient(
        colorsSpace: sRGB, colors: [variant.top, variant.bottom] as CFArray, locations: [0, 1])!
    context.drawLinearGradient(gradient, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])

    // Soft light from the top left, and a fine bright rim.
    let light = CGGradient(
        colorsSpace: sRGB, colors: [rgb(0xFFFFFF, alpha: 0.28), rgb(0xFFFFFF, alpha: 0)] as CFArray,
        locations: [0, 1])!
    context.drawRadialGradient(
        light, startCenter: CGPoint(x: 330, y: 820), startRadius: 0,
        endCenter: CGPoint(x: 330, y: 820), endRadius: 720, options: [])
    context.addPath(tile)
    context.setStrokeColor(rgb(0xFFFFFF, alpha: 0.22))
    context.setLineWidth(8)
    context.strokePath()

    // The keys, lifted off the tile by their shadow.
    context.saveGState()
    context.setShadow(
        offset: CGSize(width: 0, height: -16 * scale), blur: 30 * scale, color: rgb(0x000000, alpha: 0.38))
    let (size, centre) = markPlacement(variant)
    drawMark(
        in: context,
        transform: CGAffineTransform(translationX: 512 - 50 * size, y: centre - 50 * size).scaledBy(x: size, y: size),
        color: rgb(0xFFFFFF), shade: variant.markShade)
    context.restoreGState()

    if variant == .dev {
        drawDevBar(in: context)
    }
    context.restoreGState()
}

/// The DEV bar's height above the tile's bottom edge, on the 1024 grid.
let devBarHeight: CGFloat = 190

/// The mark's scale and vertical centre. Release fills the tile. Dev keeps the same top
/// but ends above the DEV bar, so no key is cut off.
func markPlacement(_ variant: Variant) -> (size: CGFloat, centre: CGFloat) {
    let releaseSize: CGFloat = 7.7
    guard variant == .dev else { return (releaseSize, 512) }
    let height = bounds(mark).height
    let top = 512 + releaseSize * height / 2
    let bottom = 100 + devBarHeight + 34
    return ((top - bottom) / height, (top + bottom) / 2)
}

/// A dark bar along the tile's bottom with "DEV" in large letters, readable at the sizes
/// the Dock and Finder use. The tile's clip rounds its corners.
func drawDevBar(in context: CGContext) {
    context.saveGState()
    context.setFillColor(rgb(0x1E1E1E, alpha: 0.92))
    context.fill(CGRect(x: 0, y: 0, width: 1024, height: 100 + devBarHeight))
    let text = NSAttributedString(
        string: "DEV",
        attributes: [
            .font: NSFont.systemFont(ofSize: 150, weight: .heavy),
            .foregroundColor: NSColor.white,
            .kern: 16,
        ])
    let size = text.size()
    // The kerning adds space after the last letter too; shift by half of it to centre.
    text.draw(at: CGPoint(x: 512 - size.width / 2 + 8, y: 100 + devBarHeight / 2 - size.height / 2 + 4))
    context.restoreGState()
}

// MARK: - Menu bar icon (18-point template image: black on transparent)

func drawMenuBarIcon(_ variant: Variant, in context: CGContext, scale: CGFloat) {
    context.scaleBy(x: scale, y: scale)
    // 16.5 points tall, centred.
    let size = 16.5 / bounds(mark).height
    context.beginTransparencyLayer(auxiliaryInfo: nil)
    drawMark(
        in: context,
        transform: CGAffineTransform(translationX: 9 - 50 * size, y: 9 - 50 * size).scaledBy(x: size, y: size),
        color: rgb(0x000000))
    if variant == .dev {
        // The dot sits beside the ring, with a gap cut around it.
        let dot = CGRect(x: 13.6, y: 13.4, width: 4.4, height: 4.4)
        context.setBlendMode(.clear)
        context.fillEllipse(in: dot.insetBy(dx: -1, dy: -1))
        context.setBlendMode(.normal)
        context.setFillColor(rgb(0x000000))
        context.fillEllipse(in: dot)
    }
    context.endTransparencyLayer()
}

// MARK: - Output

func png(pixels: Int, to url: URL, draw: (CGContext) -> Void) {
    let context = CGContext(
        data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpace(name: CGColorSpace.sRGB)!,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
    draw(context)
    let destination = CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, context.makeImage()!, nil)
    CGImageDestinationFinalize(destination)
}

func writeJSON(_ object: Any, to url: URL) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    try! data.write(to: url)
}

let info: [String: Any] = ["author": "xcode", "version": 1]
let fileManager = FileManager.default
try! fileManager.createDirectory(at: assets, withIntermediateDirectories: true)
writeJSON(["info": info], to: assets.appending(path: "Contents.json"))

// Every size macOS asks for: (points, scale) -> pixels.
let appIconSizes: [(points: Int, scale: Int)] = [16, 32, 128, 256, 512].flatMap { [($0, 1), ($0, 2)] }

for variant in Variant.allCases {
    let iconSet = assets.appending(path: "\(variant.appIconName).appiconset")
    try? fileManager.removeItem(at: iconSet)
    try! fileManager.createDirectory(at: iconSet, withIntermediateDirectories: true)
    var images: [[String: Any]] = []
    for (points, scale) in appIconSizes {
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        png(pixels: points * scale, to: iconSet.appending(path: name)) {
            drawAppIcon(variant, in: $0, pixels: points * scale)
        }
        images.append(["filename": name, "idiom": "mac", "scale": "\(scale)x", "size": "\(points)x\(points)"])
    }
    writeJSON(["images": images, "info": info], to: iconSet.appending(path: "Contents.json"))

    let imageSet = assets.appending(path: "\(variant.menuBarName).imageset")
    try? fileManager.removeItem(at: imageSet)
    try! fileManager.createDirectory(at: imageSet, withIntermediateDirectories: true)
    for scale in [1, 2] {
        png(pixels: 18 * scale, to: imageSet.appending(path: "menubar@\(scale)x.png")) {
            drawMenuBarIcon(variant, in: $0, scale: CGFloat(scale))
        }
    }
    writeJSON(
        [
            "images": [
                ["filename": "menubar@1x.png", "idiom": "mac", "scale": "1x"],
                ["filename": "menubar@2x.png", "idiom": "mac", "scale": "2x"],
            ],
            "info": info,
            "properties": ["template-rendering-intent": "template"],
        ],
        to: imageSet.appending(path: "Contents.json"))
}
print("Wrote icons to \(assets.path)")

// An optional side-by-side preview: both app icons, then both menu bar icons on light
// and dark menu bars, enlarged.
if CommandLine.arguments.count > 1 {
    let url = URL(fileURLWithPath: CommandLine.arguments[1])
    png(pixels: 1100, to: url) { context in
        context.setFillColor(rgb(0xECECEC))
        context.fill(CGRect(x: 0, y: 0, width: 1100, height: 1100))
        for (index, variant) in Variant.allCases.enumerated() {
            context.saveGState()
            context.translateBy(x: 30 + CGFloat(index) * 540, y: 520)
            drawAppIcon(variant, in: context, pixels: 500)
            context.restoreGState()
            for (row, bar) in [rgb(0xF6F6F6), rgb(0x2B2B2B)].enumerated() {
                let y = 300 - CGFloat(row) * 220
                context.setFillColor(bar)
                context.fill(CGRect(x: 40 + CGFloat(index) * 540, y: y, width: 480, height: 180))
                context.saveGState()
                context.translateBy(x: 40 + CGFloat(index) * 540 + 168, y: y + 18)
                context.beginTransparencyLayer(auxiliaryInfo: nil)
                drawMenuBarIcon(variant, in: context, scale: 8)
                // Template images take the menu bar's text colour.
                context.setBlendMode(.sourceIn)
                context.setFillColor(row == 0 ? rgb(0x000000) : rgb(0xFFFFFF))
                context.fill(CGRect(x: -10, y: -10, width: 40, height: 40))
                context.endTransparencyLayer()
                context.restoreGState()
            }
        }
    }
    print("Wrote preview to \(url.path)")
}

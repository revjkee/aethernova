import SwiftUI
import UIKit

public extension Color {
    
    // MARK: - Brand Palette
    static let primaryBrand = Color("PrimaryBrand") // dynamic from Assets
    static let secondaryBrand = Color("SecondaryBrand")
    static let accentAI = Color("AccentAI")
    static let error = Color("Error")
    static let warning = Color("Warning")
    static let success = Color("Success")

    // MARK: - Backgrounds
    static let backgroundMain = Color("BackgroundMain")
    static let backgroundElevated = Color("BackgroundElevated")
    static let backgroundOverlay = Color.black.opacity(0.45)

    // MARK: - Text Colors
    static let textPrimary = Color("TextPrimary")
    static let textSecondary = Color("TextSecondary")
    static let textMuted = Color.gray.opacity(0.6)

    // MARK: - System Role Based
    static func role(_ role: UserRole) -> Color {
        switch role {
        case .admin:
            return Color.red.opacity(0.9)
        case .auditor:
            return Color.orange
        case .user:
            return Color.primaryBrand
        case .ai:
            return Color.accentAI
        }
    }

    // MARK: - Intent & Feedback Status
    static func intentStatus(_ status: IntentResultStatus?) -> Color {
        switch status {
        case .success: return .success
        case .failed: return .error
        case .rejected: return .warning
        case .none: return .gray
        }
    }

    // MARK: - Dynamic theme support
    static var adaptiveBackground: Color {
        Color(UIColor { traitCollection in
            traitCollection.userInterfaceStyle == .dark
                ? UIColor(named: "BackgroundMainDark") ?? .black
                : UIColor(named: "BackgroundMainLight") ?? .white
        })
    }

    // MARK: - Contrast fallback
    static func highContrastSafe(_ light: Color, _ dark: Color) -> Color {
        Color(UIColor { trait in
            switch trait.userInterfaceStyle {
            case .dark: return UIColor(dark)
            default: return UIColor(light)
            }
        })
    }

    // MARK: - AI & ZT UI special tokens
    static let aiIntentHighlight = Color("AIIntentHighlight") // e.g. blue pulse
    static let zeroTrustCaution = Color.yellow.opacity(0.85)
    static let criticalSecurity = Color.red.opacity(0.95)

    // MARK: - Utilities
    static func withOpacity(_ color: Color, _ value: Double) -> Color {
        color.opacity(value)
    }

    static func fromHex(_ hex: String) -> Color {
        var hexSanitized = hex.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if hexSanitized.hasPrefix("#") { hexSanitized.removeFirst() }

        var rgb: UInt64 = 0
        Scanner(string: hexSanitized).scanHexInt64(&rgb)

        let r = Double((rgb & 0xFF0000) >> 16) / 255
        let g = Double((rgb & 0x00FF00) >> 8) / 255
        let b = Double(rgb & 0x0000FF) / 255

        return Color(red: r, green: g, blue: b)
    }
}

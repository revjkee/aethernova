import Foundation
import UIKit
import AVFoundation
import CoreHaptics
import OSLog

/// Управление тактильной, звуковой и мультимодальной обратной связью
final class HapticManager {

    static let shared = HapticManager()

    private let logger = Logger(subsystem: "com.teslaai.feedback", category: "HapticManager")

    private var engine: CHHapticEngine?
    private var player: AVAudioPlayer?

    enum FeedbackType {
        case light, medium, heavy, success, warning, error, aiIntent, secureAction
    }

    private init() {
        prepareHaptics()
    }

    func trigger(_ type: FeedbackType) {
        switch type {
        case .light:
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            playSystemSound(name: "tap_light", fallback: 1104)
        case .medium:
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            playSystemSound(name: "tap_medium", fallback: 1105)
        case .heavy:
            UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
            playSystemSound(name: "tap_heavy", fallback: 1106)
        case .success:
            UINotificationFeedbackGenerator().notificationOccurred(.success)
            playSystemSound(name: "success", fallback: 1025)
        case .warning:
            UINotificationFeedbackGenerator().notificationOccurred(.warning)
            playSystemSound(name: "warning", fallback: 1022)
        case .error:
            UINotificationFeedbackGenerator().notificationOccurred(.error)
            playSystemSound(name: "error", fallback: 1023)
        case .aiIntent:
            performCustomHaptic(intensity: 0.7, sharpness: 0.8)
            playSystemSound(name: "ai_intent", fallback: 1126)
        case .secureAction:
            performCustomHaptic(intensity: 0.9, sharpness: 1.0)
            playSystemSound(name: "secure_click", fallback: 1127)
        }
    }

    // MARK: - CoreHaptics

    private func prepareHaptics() {
        guard CHHapticEngine.capabilitiesForHardware().supportsHaptics else {
            logger.warning("Haptics not supported on this device")
            return
        }

        do {
            engine = try CHHapticEngine()
            try engine?.start()
            logger.info("Haptic engine initialized")
        } catch {
            logger.error("Failed to start haptic engine: \(error.localizedDescription)")
        }
    }

    private func performCustomHaptic(intensity: Float, sharpness: Float) {
        guard let engine = engine else { return }

        let event = CHHapticEvent(
            eventType: .hapticTransient,
            parameters: [
                CHHapticEventParameter(parameterID: .hapticIntensity, value: intensity),
                CHHapticEventParameter(parameterID: .hapticSharpness, value: sharpness)
            ],
            relativeTime: 0
        )

        do {
            let pattern = try CHHapticPattern(events: [event], parameters: [])
            let player = try engine.makePlayer(with: pattern)
            try player.start(atTime: 0)
        } catch {
            logger.error("Failed to play custom haptic: \(error.localizedDescription)")
        }
    }

    // MARK: - Звук

    private func playSystemSound(name: String, fallback: SystemSoundID) {
        guard let soundURL = Bundle.main.url(forResource: name, withExtension: "wav") else {
            AudioServicesPlaySystemSound(fallback)
            return
        }

        do {
            player = try AVAudioPlayer(contentsOf: soundURL)
            player?.prepareToPlay()
            player?.play()
        } catch {
            logger.warning("Audio fallback to system sound: \(fallback)")
            AudioServicesPlaySystemSound(fallback)
        }
    }
}

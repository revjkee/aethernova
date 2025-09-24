import Foundation
import CoreMotion
import AVFoundation
import OSLog
import Combine
import UIKit

final class SensorBridge: NSObject, ObservableObject {

    // MARK: - Singleton
    static let shared = SensorBridge()

    // MARK: - Sensors
    private let motionManager = CMMotionManager()
    private let captureSession = AVCaptureSession()

    // MARK: - Publishers
    @Published var accelerometerData: CMAcceleration?
    @Published var deviceOrientation: UIDeviceOrientation = .unknown
    @Published var cameraAccessGranted: Bool = false
    @Published var isMotionActive: Bool = false

    // MARK: - Internals
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "SensorBridge")
    private var cancellables = Set<AnyCancellable>()
    private let ethics = EthicsEngine.shared
    private let feedback = FeedbackRecorder.shared

    // MARK: - Setup Motion
    func startMotionUpdates(updateInterval: TimeInterval = 0.1) {
        guard motionManager.isAccelerometerAvailable else {
            logger.error("Accelerometer not available")
            return
        }

        motionManager.accelerometerUpdateInterval = updateInterval
        motionManager.startAccelerometerUpdates(to: .main) { [weak self] data, error in
            guard let self = self, let data = data else { return }

            if !self.ethics.allowSensor(.motion) {
                self.logger.fault("Motion data blocked by ethics")
                self.feedback.record(event: .sensorBlocked("motion"))
                return
            }

            self.accelerometerData = data.acceleration
            self.isMotionActive = true
            self.feedback.record(event: .sensorUsed("motion"))
        }

        logger.notice("Started accelerometer updates")
    }

    func stopMotionUpdates() {
        motionManager.stopAccelerometerUpdates()
        isMotionActive = false
        logger.info("Stopped accelerometer")
    }

    // MARK: - Setup Camera Access (No Video Feed)
    func requestCameraAccess() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            self.cameraAccessGranted = true
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    self.cameraAccessGranted = granted
                    if granted {
                        self.logger.notice("Camera access granted")
                        self.feedback.record(event: .sensorUsed("camera"))
                    } else {
                        self.logger.warning("Camera access denied")
                        self.feedback.record(event: .sensorBlocked("camera"))
                    }
                }
            }
        default:
            self.logger.warning("Camera permission not authorized")
            self.cameraAccessGranted = false
        }
    }

    func isCameraAvailable() -> Bool {
        return AVCaptureDevice.default(for: .video) != nil
    }

    // MARK: - Orientation Tracking
    func beginOrientationTracking() {
        UIDevice.current.beginGeneratingDeviceOrientationNotifications()

        NotificationCenter.default.publisher(for: UIDevice.orientationDidChangeNotification)
            .sink { _ in
                self.deviceOrientation = UIDevice.current.orientation
                self.logger.debug("Device orientation changed to: \(self.deviceOrientation.rawValue)")
            }
            .store(in: &cancellables)

        logger.notice("Started orientation tracking")
    }

    func stopOrientationTracking() {
        UIDevice.current.endGeneratingDeviceOrientationNotifications()
        logger.info("Stopped orientation tracking")
    }

    // MARK: - Audit and Security
    func printSensorStatus() {
        logger.info("Sensor Status:")
        logger.info("- Accelerometer available: \(motionManager.isAccelerometerAvailable)")
        logger.info("- Motion active: \(isMotionActive)")
        logger.info("- Camera access: \(cameraAccessGranted)")
        logger.info("- Orientation: \(deviceOrientation.rawValue)")
    }
}

// MARK: - Ethics Rules Extension
extension EthicsEngine {
    enum SensorType {
        case motion, camera, microphone
    }

    func allowSensor(_ type: SensorBridge.SensorType) -> Bool {
        // AI-driven rule check (mocked for industrial version)
        switch type {
        case .motion: return true
        case .camera: return true
        case .microphone: return false // requires user override
        }
    }
}

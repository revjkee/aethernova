import Foundation
import AVFoundation
import OSLog

/// Рекордер и архиватор пользовательской обратной связи, включая текст, голос, действия и эмоции
final class FeedbackRecorder: NSObject, AVAudioRecorderDelegate {

    static let shared = FeedbackRecorder()

    private let logger = Logger(subsystem: "com.teslaai.feedback", category: "FeedbackRecorder")

    private var audioRecorder: AVAudioRecorder?
    private let feedbackQueue = DispatchQueue(label: "com.teslaai.feedback.queue")
    private var sessionID: String = UUID().uuidString

    struct FeedbackEntry: Codable {
        let sessionID: String
        let timestamp: Date
        let userID: String
        let messageType: MessageType
        let content: String?
        let audioFile: String?
        let contextTags: [String]
    }

    enum MessageType: String, Codable {
        case text, voice, gesture, error, intent
    }

    private(set) var entries: [FeedbackEntry] = []

    private override init() {
        super.init()
    }

    // MARK: - Text Feedback

    func recordTextFeedback(userID: String, content: String, tags: [String]) {
        let entry = FeedbackEntry(
            sessionID: sessionID,
            timestamp: Date(),
            userID: userID,
            messageType: .text,
            content: content,
            audioFile: nil,
            contextTags: tags
        )
        append(entry)
        logger.info("Text feedback recorded")
    }

    // MARK: - Voice Feedback

    func startVoiceRecording(userID: String, tags: [String]) {
        let fileName = "voice_\(UUID().uuidString).m4a"
        let audioURL = getDocumentsDirectory().appendingPathComponent(fileName)

        let settings = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44100,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.high.rawValue
        ]

        do {
            audioRecorder = try AVAudioRecorder(url: audioURL, settings: settings)
            audioRecorder?.delegate = self
            audioRecorder?.record()
            logger.info("Started voice feedback recording")
        } catch {
            logger.error("Failed to start audio recording: \(error.localizedDescription)")
        }
    }

    func stopVoiceRecording(userID: String, tags: [String]) {
        audioRecorder?.stop()
        guard let url = audioRecorder?.url else { return }

        let entry = FeedbackEntry(
            sessionID: sessionID,
            timestamp: Date(),
            userID: userID,
            messageType: .voice,
            content: nil,
            audioFile: url.lastPathComponent,
            contextTags: tags
        )
        append(entry)
        logger.info("Voice feedback recorded at \(url.lastPathComponent)")
    }

    // MARK: - Intent/Error Feedback

    func recordSystemFeedback(type: MessageType, userID: String, content: String?, tags: [String]) {
        guard type == .intent || type == .error || type == .gesture else { return }

        let entry = FeedbackEntry(
            sessionID: sessionID,
            timestamp: Date(),
            userID: userID,
            messageType: type,
            content: content,
            audioFile: nil,
            contextTags: tags
        )
        append(entry)
        logger.notice("System feedback (\(type.rawValue)) recorded")
    }

    // MARK: - Utilities

    private func append(_ entry: FeedbackEntry) {
        feedbackQueue.sync {
            entries.append(entry)
        }
    }

    func exportSessionFeedback(to filename: String) -> URL? {
        let url = getDocumentsDirectory().appendingPathComponent(filename)
        do {
            let data = try JSONEncoder().encode(entries)
            try data.write(to: url)
            logger.info("Exported feedback to \(url.lastPathComponent)")
            return url
        } catch {
            logger.error("Export failed: \(error.localizedDescription)")
            return nil
        }
    }

    private func getDocumentsDirectory() -> URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    func resetSession() {
        sessionID = UUID().uuidString
        entries.removeAll()
        logger.debug("Feedback session reset")
    }
}

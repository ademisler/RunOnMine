import Foundation
import AVFoundation

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(("ERROR: \(message)\n").data(using: .utf8)!)
    exit(code)
}

guard CommandLine.arguments.count >= 3 else {
    fail("usage: runonmine-record-audio <output.caf> <max-seconds> [end-silence-ms] [speech-threshold-db] [start-sound]", code: 2)
}

let outputPath = CommandLine.arguments[1]
guard let maxSeconds = Double(CommandLine.arguments[2]), maxSeconds > 0, maxSeconds <= 60 else {
    fail("max-seconds must be > 0 and <= 60", code: 2)
}
let endSilenceMs = CommandLine.arguments.count >= 4 ? (Double(CommandLine.arguments[3]) ?? 2500) : 2500
let speechThresholdDb = CommandLine.arguments.count >= 5 ? (Float(CommandLine.arguments[4]) ?? -43.0) : -43.0
let endSilenceSeconds = max(0.5, min(4.0, endSilenceMs / 1000.0))
let startSoundPath = CommandLine.arguments.count >= 6 ? CommandLine.arguments[5] : ""
let resultPath = CommandLine.arguments.count >= 7 ? CommandLine.arguments[6] : ""
let minimumSpeechSeconds = 0.16

func microphoneAuthorized() -> Bool {
    switch AVCaptureDevice.authorizationStatus(for: .audio) {
    case .authorized:
        return true
    case .denied, .restricted:
        return false
    case .notDetermined:
        let semaphore = DispatchSemaphore(value: 0)
        var granted = false
        AVCaptureDevice.requestAccess(for: .audio) { allowed in
            granted = allowed
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 30)
        return granted && AVCaptureDevice.authorizationStatus(for: .audio) == .authorized
    @unknown default:
        return false
    }
}

guard microphoneAuthorized() else {
    fail("microphone permission denied; enable Microphone access for RunOnMine Voice Recorder in System Settings")
}

let engine = AVAudioEngine()
let input = engine.inputNode
var voiceProcessingEnabled = false

do {
    try input.setVoiceProcessingEnabled(true)
    voiceProcessingEnabled = input.isVoiceProcessingEnabled
} catch {
    // Voice processing is an accuracy enhancement, not a hard requirement.
    FileHandle.standardError.write(("WARN: voice processing unavailable: \(error)\n").data(using: .utf8)!)
}

let format = input.outputFormat(forBus: 0)
if format.sampleRate <= 0 || format.channelCount == 0 {
    fail("no usable microphone input format")
}

let outputURL = URL(fileURLWithPath: outputPath)
try? FileManager.default.removeItem(at: outputURL)

let audioFile: AVAudioFile
do {
    audioFile = try AVAudioFile(
        forWriting: outputURL,
        settings: format.settings,
        commonFormat: format.commonFormat,
        interleaved: format.isInterleaved
    )
} catch {
    fail("cannot create audio file: \(error)")
}

let stateLock = NSLock()
var writeError: Error?
var speechDetected = false
var candidateSpeechSeconds = 0.0
var silenceSeconds = 0.0
var autoStopped = false
var shouldStop = false
var peakDb: Float = -120.0
var armed = false

func levelDb(_ buffer: AVAudioPCMBuffer) -> Float {
    let frames = Int(buffer.frameLength)
    if frames == 0 { return -120.0 }

    if let channels = buffer.floatChannelData {
        let samples = channels[0]
        var sum: Double = 0
        for i in 0..<frames {
            let v = Double(samples[i])
            sum += v * v
        }
        let rms = sqrt(sum / Double(frames))
        return Float(20.0 * log10(max(rms, 0.000001)))
    }

    if let channels = buffer.int16ChannelData {
        let samples = channels[0]
        var sum: Double = 0
        for i in 0..<frames {
            let v = Double(samples[i]) / 32768.0
            sum += v * v
        }
        let rms = sqrt(sum / Double(frames))
        return Float(20.0 * log10(max(rms, 0.000001)))
    }

    return -120.0
}

var recordingStartedAt = Date()
input.installTap(onBus: 0, bufferSize: 1024, format: format) { buffer, _ in
    let db = levelDb(buffer)
    let duration = Double(buffer.frameLength) / format.sampleRate

    stateLock.lock()
    defer { stateLock.unlock() }
    guard armed else { return }

    if db > peakDb { peakDb = db }

    if writeError == nil {
        do {
            try audioFile.write(from: buffer)
        } catch {
            writeError = error
        }
    }

    // Energy VAD is used only to decide when to stop recording. The actual
    // transcription is segmented again with Silero VAD in whisper.cpp.
    if db >= speechThresholdDb {
        candidateSpeechSeconds += duration
        silenceSeconds = 0
        if candidateSpeechSeconds >= minimumSpeechSeconds {
            speechDetected = true
        }
    } else if speechDetected {
        silenceSeconds += duration
        if silenceSeconds >= endSilenceSeconds {
            autoStopped = true
            shouldStop = true
        }
    } else {
        // Require contiguous speech before opening the gate.
        candidateSpeechSeconds = max(0, candidateSpeechSeconds - duration * 0.5)
    }
}

do {
    try engine.start()
} catch {
    input.removeTap(onBus: 0)
    fail("cannot start microphone capture: \(error)")
}

// Play the start cue only after the audio engine is fully running. The tap is
// deliberately disarmed during the cue so the cue itself cannot trigger VAD or
// leak into the transcript. This removes the startup gap that clipped the first
// words when the cue was played before launching the recorder process.
if !startSoundPath.isEmpty && FileManager.default.fileExists(atPath: startSoundPath) {
    do {
        let player = try AVAudioPlayer(contentsOf: URL(fileURLWithPath: startSoundPath))
        player.prepareToPlay()
        player.play()
        while player.isPlaying { Thread.sleep(forTimeInterval: 0.01) }
    } catch {
        FileHandle.standardError.write(("WARN: start cue failed: \(error)\n").data(using: .utf8)!)
    }
}

stateLock.lock()
armed = true
stateLock.unlock()
recordingStartedAt = Date()

while Date().timeIntervalSince(recordingStartedAt) < maxSeconds {
    Thread.sleep(forTimeInterval: 0.04)
    stateLock.lock()
    let done = shouldStop || writeError != nil
    stateLock.unlock()
    if done { break }
}

engine.stop()
input.removeTap(onBus: 0)

stateLock.lock()
let finalWriteError = writeError
let finalSpeechDetected = speechDetected
let finalAutoStopped = autoStopped
let finalPeakDb = peakDb
stateLock.unlock()

if let finalWriteError {
    fail("audio write failed: \(finalWriteError)")
}

let durationSeconds = format.sampleRate > 0 ? Double(audioFile.length) / format.sampleRate : Date().timeIntervalSince(recordingStartedAt)
let result: [String: Any] = [
    "durationSeconds": Double(String(format: "%.3f", durationSeconds)) ?? durationSeconds,
    "speechDetected": finalSpeechDetected,
    "autoStopped": finalAutoStopped,
    "voiceProcessing": voiceProcessingEnabled,
    "peakDb": Double(finalPeakDb),
    "sampleRate": Int(format.sampleRate),
    "channels": Int(format.channelCount),
]
if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
   let json = String(data: data, encoding: .utf8) {
    print(json)
    if !resultPath.isEmpty {
        let resultURL = URL(fileURLWithPath: resultPath)
        do {
            try data.write(to: resultURL, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: resultPath)
        } catch {
            fail("cannot write capture metadata: \(error)")
        }
    }
} else {
    fail("cannot serialize capture metadata")
}

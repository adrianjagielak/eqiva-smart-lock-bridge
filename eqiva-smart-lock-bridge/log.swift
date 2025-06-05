//
//  log.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 04/06/2025.
//

import Foundation

var onLogUpdated: (() -> Void)?
var lastLogLines: [String] = []

private let logQueue = DispatchQueue(label: "dev.adrianjagielak.eqiva-smart-lock-bridge.logger", qos: .background)
private let maxLogSize: UInt64 = 10 * 1024 * 1024 // 10MB

func log(_ message: String) {
    let timestamp = logTimestamp()
    let logMessage = "\(timestamp) \(message)\n"

    logQueue.async {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let logURL = documents.appendingPathComponent("eqiva-smart-lock-bridge.log")
        let oldLogURL = documents.appendingPathComponent("eqiva-smart-lock-bridge.log.old")
        
        // Rotate if file too large
        if let attrs = try? FileManager.default.attributesOfItem(atPath: logURL.path),
           let fileSize = attrs[.size] as? UInt64,
           fileSize >= maxLogSize {
            
            // Delete old log if exists
            if FileManager.default.fileExists(atPath: oldLogURL.path) {
                try? FileManager.default.removeItem(at: oldLogURL)
            }
            // Rename current to old
            try? FileManager.default.moveItem(at: logURL, to: oldLogURL)
        }
        
        // Write message
        if let data = logMessage.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logURL.path) {
                if let handle = try? FileHandle(forWritingTo: logURL) {
                    handle.seekToEndOfFile()
                    handle.write(data)
                    handle.closeFile()
                }
            } else {
                try? data.write(to: logURL)
            }
        }
        
        print(message)
        DispatchQueue.main.async {
            lastLogLines.append("\(timestamp) \(message)")
            if lastLogLines.count > 50 {
                lastLogLines.removeFirst()
            }
            onLogUpdated?()
        }
    }
}

/// Returns the current local date-time in the form:
/// [YYYY-MM-DD HH:mm:ss.SSS]
fileprivate func logTimestamp() -> String {
    // A static DateFormatter is lazily created once and reused.
    // This is thread-safe in Swift.
    struct Formatter {
        static let shared: DateFormatter = {
            let df = DateFormatter()
            df.locale = Locale(identifier: "en_US_POSIX") // fixed-format locale
            df.timeZone = .current                        // use .utc for UTC
            df.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
            return df
        }()
    }

    return "[\(Formatter.shared.string(from: Date()))]"
}

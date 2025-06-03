//
//  logTimestamp.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 03/06/2025.
//

import Foundation

/// Returns the current local date-time in the form:
/// [YYYY-MM-DD HH:mm:ss.SSS]
func logTimestamp() -> String {
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

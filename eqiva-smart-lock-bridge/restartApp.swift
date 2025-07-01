//
//  restartApp.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/07/2025.
//

import Foundation

func restartApp() {
    log("Restarting the app...")
    let path = Bundle.main.bundlePath
    let task = Process()
    task.launchPath = "/usr/bin/open"
    task.arguments = [path]
    do {
        try task.run()
        exit(0)
    } catch {
        log("Failed to restart app: \(error)")
    }
}

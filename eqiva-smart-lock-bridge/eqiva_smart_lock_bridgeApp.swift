//
//  eqiva_smart_lock_bridgeApp.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 04/06/2025.
//

import SwiftUI

@main
struct eqiva_smart_lock_bridgeApp: App {
    @State var hasStarted = false
    @AppStorage("userKeyHex") var userKeyHex = ""
    @AppStorage("userID") var userID = ""
    @AppStorage("webSocketURL") var webSocketURL = "ws://localhost:9099"

    func start() {
        DispatchQueue.main.async {
            guard !hasStarted else { return }
            hasStarted = true
            
            let userKeyHex = self.userKeyHex
            let userID = UInt8(self.userID)
            let webSocketURL = URL(string: self.webSocketURL)
            
            guard !userKeyHex.isEmpty, let userID = userID, let webSocketURL = webSocketURL else {
                log("Please provide a valid User Key, User ID, and WebSocket URL, then restart the app.")
                return
            }
            
            log("Starting in 5s...")
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                mainEntrypoint(userKeyHex: userKeyHex, userID: userID, webSocketURL: webSocketURL)
            }
        }
    }

    var body: some Scene {
        let _ = start()
        
        MenuBarExtra("Eqiva Smart Lock Bridge", systemImage: "dot.radiowaves.left.and.right") {
            ContentView()
        }
        .menuBarExtraStyle(.window)
    }
}

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
    
    func start() {
        DispatchQueue.main.async {
            guard !hasStarted else { return }
            hasStarted = true
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                mainEntrypoint()
            }
        }
    }

    var body: some Scene {
        let _ = start()
        
        Window(Text("Eqiva Smart Lock Bridge"), id: "window0") {
            ContentView()
                }
                .menuBarExtraStyle(.window)
    }
}

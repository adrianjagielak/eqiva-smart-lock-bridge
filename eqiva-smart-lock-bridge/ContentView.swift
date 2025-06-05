//
//  ContentView.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 04/06/2025.
//

import SwiftUI

struct ContentView: View {
    @State var hasStarted = false
    @State var lastLogLinesCache: [String] = []

    func start() {
        // dirty hack; I don't care
        
        DispatchQueue.main.async {
            lastLogLinesCache = lastLogLines
        }
        onLogUpdated = {
            lastLogLinesCache = lastLogLines
        }
    }

    var body: some View {
        let _ = start()
        
        ScrollView {
            VStack(alignment: .leading) {
                LaunchAtLoginCheckbox()
                    .padding(.bottom)
                Text("Full log can be found at: ~/Library/Containers/dev.adrianjagielak.eqiva-smart-lock-bridge/eqiva-smart-lock-bridge.log")
                    .padding(.bottom)
                Text("Last 50 log lines:")
                    .padding(.bottom)
                Text(lastLogLinesCache.joined())
            }
            .padding()
        }
        .frame(width: 800, height: 500)
    }
}

#Preview {
    ContentView()
}

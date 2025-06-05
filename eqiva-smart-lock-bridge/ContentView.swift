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
    @AppStorage("userKeyHex") var userKeyHex = ""
    @AppStorage("userID") var userID = ""
    @AppStorage("webSocketURL") var webSocketURL = "ws://localhost:9099"

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
        
        VStack {
            Text("Eqiva Smart Lock Bridge")
                .font(.title2)
                .padding()
            HStack() {
                LaunchAtLoginCheckbox()
                Spacer()
                Button("Exit") {
                    NSApplication.shared.terminate(nil)
                }
            }
            .padding(.leading)
            .padding(.trailing)
            Divider()
            HStack {
                VStack(alignment: .leading) {
                    Text("User Key")
                    TextField("abcdef1234567890abcdef1234567890", text: $userKeyHex)
                        .textFieldStyle(.roundedBorder)
                }
                VStack(alignment: .leading) {
                    Text("User ID")
                    TextField("1", text: $userID)
                        .textFieldStyle(.roundedBorder)
                }
                VStack(alignment: .leading) {
                    Text("WebSocket URL")
                    TextField("ws://localhost:9099", text: $webSocketURL)
                        .textFieldStyle(.roundedBorder)
                }
            }
            .padding(.leading)
            .padding(.trailing)
            Divider()
            ScrollView {
                Text(lastLogLinesCache.joined(separator: "\n"))
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                .rotationEffect(.degrees(180))
            }
            .rotationEffect(.degrees(180))
            .frame(width: 800, height: 500)
            Divider()
            Text("Full log can be found at: ~/Library/Containers/dev.adrianjagielak.eqiva-smart-lock-bridge/eqiva-smart-lock-bridge.log")
                .padding(.bottom)
        }
    }
}

#Preview {
    ContentView()
}

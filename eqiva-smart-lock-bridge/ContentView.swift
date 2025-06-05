//
//  ContentView.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 04/06/2025.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Text("Running.")
            LaunchAtLoginCheckbox()
        }
        .padding()
    }
}

#Preview {
    ContentView()
}

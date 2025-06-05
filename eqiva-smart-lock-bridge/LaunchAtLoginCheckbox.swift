//
//  LaunchAtLoginCheckbox.swift
//
//  Created by Adrian Jagielak on 16/03/2024.
//

#if os(macOS)

import Foundation
import ServiceManagement
import SwiftUI

@available(macOS 13.0, *)
struct LaunchAtLoginCheckbox: View {
    @State var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        Toggle(isOn: $launchAtLogin) {
            Text("Launch at Login")
        }
        .toggleStyle(.checkbox)
        .onChange(of: launchAtLogin) { oldValue, newValue in
            if newValue {
                do {
                    try SMAppService.mainApp.register()
                } catch {
                    log("Unable to register launch agent: \(error)")
                }
            } else {
                do {
                    try SMAppService.mainApp.unregister()
                } catch {
                    log("Unable to unregister launch agent: \(error)")
                }
            }
        }
    }
}

#endif

// KeyBle+Commands.swift
// High-level commands extension for KeyBle

import Foundation

extension KeyBle {
    func lock() {
        commandQueue.async {
            self.sendMessage(type: .command, payload: Data([0x00]))
        }
    }

    func unlock() {
        commandQueue.async {
            self.sendMessage(type: .command, payload: Data([0x01]))
        }
    }

    func open() {
        commandQueue.async {
            if self.lockStatusID == 4 { return }
            self.sendMessage(type: .command, payload: Data([0x02]))
        }
    }

    func toggle() {
        commandQueue.async {
            guard let status = self.lockStatusID else {
                self.requestStatus()
                return
            }
            switch status {
                case 2, 4: self.lock()
                case 3:     self.unlock()
                default:    print("[KeyBle] Cannot toggle from status \(status)")
            }
        }
    }

    func requestStatus() {
        commandQueue.async {
            let now = Date()
            let cal = Calendar.current
            let year = UInt8(cal.component(.year, from: now) - 2000)
            let month = UInt8(cal.component(.month, from: now))
            let day = UInt8(cal.component(.day, from: now))
            let hour = UInt8(cal.component(.hour, from: now))
            let minute = UInt8(cal.component(.minute, from: now))
            let second = UInt8(cal.component(.second, from: now))
            let payload = Data([year, month, day, hour, minute, second])
            self.sendMessage(type: .statusRequest, payload: payload)
        }
    }
}

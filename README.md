# Eqiva eQ-3 Smart Lock HomeKit Bridge

A macOS Swift controller program for the Eqiva eQ-3 Bluetooth Smart Lock, paired with a Homebridge plugin to expose it to Homebridge and HomeKit. Unlike the notoriously unstable Linux BLE stack, this solution leverages the robust and reliable CoreBluetooth stack native to macOS (similar to iOS), providing a constant and stable connection to the lock.

## What This Is

This is a personal project I built to control my Eqiva eQ-3 Bluetooth Smart Lock reliably from macOS, and integrate it into my HomeKit setup via Homebridge. I’m publishing it in case it’s helpful to anyone else with similar needs. Also, this README is for future me if I ever need to configure this thing again 😂

## Features

- macOS Swift menu bar app (runs as an icon in the top right of your screen) for controlling the lock with a super stable CoreBluetooth stack.
- Homebridge plugin to expose the lock to HomeKit.
- WebSocket communication between the app and plugin ensures fast, local integration.
- GUI app is required due to macOS limitations on Bluetooth access for auto-launched background/CLI apps.
* Manual override switches: Due to occasional firmware quirks where the lock can end up in an incorrect or unknown state (e.g., stuck or misreporting its status), the plugin includes additional HomeKit switches for **Lock**, **Unlock**, and **Open**. These act as emergency controls, allowing you to manually force a command regardless of what state HomeKit thinks the lock is in. This is particularly helpful when the lock jams or becomes unresponsive to standard commands.

  > 💡 **Tip:** To avoid cluttering the lock accessory view, go into the lock's settings in the Home app, and enable **Show as Separate Tiles** to hide manual override switches from the default Home view.

Let me know if you'd like that tip styled differently or moved into its own section.


## Getting Started

### 1. Get Your Credentials

You need a `userKey` and `userID` from your lock. Use the [`keyble-registeruser`](https://github.com/oyooyo/keyble) command-line tool to obtain these.

### 2. Configure the Swift App

Edit `eqiva-smart-lock-bridge/MainEntrypoint.swift` and insert your `userKey` and `userID` in the appropriate section.

### 3. Build and Run the Swift App

Build the app using Xcode and run it. It must remain running, as it maintains the active BLE connection to your lock.

### 4. Install the Homebridge Plugin

Search for `homebridge-eqiva-swift-bridge` in the Homebridge UI and install it. It's published to NPM and can be installed like any other Homebridge plugin.

### 5. Make Sure They Run on the Same macOS Machine

Both the Swift app and Homebridge plugin **must** run on the same macOS machine, as they communicate over WebSocket via `localhost`.

> You *can* modify the code to communicate over LAN if you want to run them on separate machines, but that's not the default behavior.

### 6. Bluetooth Range Matters

The Eqiva eQ-3 lock has terrible BLE range. Make sure the Mac running this is **physically close** to the lock. I’ve got a Mac mini in the hallway about 2 meters from the lock and it works great.

## Auto-Launching the Swift App on Boot

Since macOS doesn’t allow Bluetooth access from CLI apps started via LaunchAgents or LaunchDaemons, this app needs to be launched as a GUI application. Enable the "Launch at Login" option to automatically start the app at login.

---

## Final Note

This was built to scratch my own itch, but if you have the same lock and a Mac nearby, this might be just the fix you’re looking for.


import {
  Service,
  CharacteristicValue,
  PlatformAccessory,
} from 'homebridge';
import { SwiftBridge } from './websocket.js';
import { StatusMessage, SwiftLockState } from './types.js';
import { HomebridgeEqivaSwiftBridgePlatform } from './platform.js';
import { sortStatusJsonForLogging } from './utils.js';

export class EqivaLockAccessory {
  private readonly lockService: Service;
  private readonly batteryService: Service;

  private targetState?: number;

  private targetStateResolver?: () => void;

  constructor(
    private readonly platform: HomebridgeEqivaSwiftBridgePlatform,
    private readonly accessory: PlatformAccessory,
    private readonly swift: SwiftBridge,
  ) {
    this.accessory.getService(this.platform.Service.AccessoryInformation)!
      .setCharacteristic(this.platform.Characteristic.Manufacturer, this.platform.config.accessoryManufacturer)
      .setCharacteristic(this.platform.Characteristic.Model, this.platform.config.accessoryModel)
      .setCharacteristic(this.platform.Characteristic.SerialNumber, this.platform.config.accessorySerial)
      .setCharacteristic(this.platform.Characteristic.FirmwareRevision, this.platform.config.accessoryFirmwareRevision);

    this.lockService = this.accessory.getService(this.platform.Service.LockMechanism)
      || this.accessory.addService(this.platform.Service.LockMechanism);
    this.batteryService = this.accessory.getService(this.platform.Service.Battery)
      || this.accessory.addService(this.platform.Service.Battery);

    // HomeKit → Swift
    this.lockService.getCharacteristic(this.platform.Characteristic.LockTargetState)
      .onSet(this.handleTargetStateSet.bind(this));

    // Swift → HomeKit
    this.swift.on('status', (msg: StatusMessage) => this.handleStatus(msg));

    // Important: Even on the latest firmware, it has been observed that when the lock fails to close properly,
    // it may incorrectly report its state as unknown (0), unlocked (2), or locked (3), seemingly at random.
    // Since HomeKit does not support requesting a state it already believes is current, we cannot simply resend a command to correct this.
    // Therefore, it is important to provide manual override switches that allow us to explicitly send "lock" (0), "unlock" (1), or "open" (2) commands.
    // These switches act as a fallback mechanism to manually recover from incorrect or stuck states,
    // particularly useful when the lock becomes jammed and does not respond to the standard "unlock" command.
    (this.accessory.getServiceById(this.platform.Service.Switch, 'Lock') ||
      this.accessory.addService(new this.platform.Service.Switch('Lock', 'Lock')))
      .getCharacteristic(this.platform.Characteristic.On)
      .onSet(() => this.swift.send('lock'));
    (this.accessory.getServiceById(this.platform.Service.Switch, 'Unlock') ||
      this.accessory.addService(new this.platform.Service.Switch('Unlock', 'Unlock')))
      .getCharacteristic(this.platform.Characteristic.On)
      .onSet(() => this.swift.send('unlock'));
    (this.accessory.getServiceById(this.platform.Service.Switch, 'Open') ||
      this.accessory.addService(new this.platform.Service.Switch('Open', 'Open')))
      .getCharacteristic(this.platform.Characteristic.On)
      .onSet(() => this.swift.send('open'));
  }

  // --------------------------------------------------------------------------

  private handleTargetStateSet(value: CharacteristicValue): Promise<void> {
    this.platform.log.debug('HomeKit target state:', value);

    // Resolve the pending set Promise if any
    if (this.targetStateResolver) {
      this.targetStateResolver();
      this.targetStateResolver = undefined;
    }

    return new Promise<void>((resolve) => {
      // Send lock/unlock command to Swift
      if (value === this.platform.Characteristic.LockTargetState.SECURED) {
        this.swift.send('lock');
      } else {
        this.swift.send('unlock');
      }

      this.targetState = value as number;

      // Store the resolver to be called when a stable state is received
      this.targetStateResolver = resolve;
    });
  }

  private handleStatus(msg: StatusMessage): void {
    this.platform.log.debug('Status from Swift:', sortStatusJsonForLogging(msg));

    if (msg.state !== SwiftLockState.moving) {
      const currentState = this.swiftToHKCurrent(msg.state);
      this.lockService.updateCharacteristic(this.platform.Characteristic.LockCurrentState, currentState);

      // Resolve the pending set Promise if any
      if (this.targetStateResolver) {
        this.targetStateResolver();
        this.targetStateResolver = undefined;
      }

      if (this.targetState) {
        this.lockService.updateCharacteristic(this.platform.Characteristic.LockTargetState, this.targetState);
      }
    }
    
    const batteryLevel = msg.batteryLow
      ? this.platform.Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW
      : this.platform.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL;

    this.batteryService.updateCharacteristic(this.platform.Characteristic.StatusLowBattery, batteryLevel);
  }

  // --------------------------------------------------------------------------
  private swiftToHKCurrent(state: SwiftLockState): number {
    switch (state) {
    case SwiftLockState.locked:
      return this.platform.Characteristic.LockCurrentState.SECURED;
    case SwiftLockState.unlocked:
    case SwiftLockState.opened:
      return this.platform.Characteristic.LockCurrentState.UNSECURED;
    case SwiftLockState.unknownProbablyJammed:
      return this.platform.Characteristic.LockCurrentState.JAMMED;
    case SwiftLockState.moving:
    case SwiftLockState.trulyUnkonwn:
    default:
      return this.platform.Characteristic.LockCurrentState.UNKNOWN;
    }
  }
}
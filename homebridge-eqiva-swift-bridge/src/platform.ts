import {
  API,
  Logging,
  DynamicPlatformPlugin,
  PlatformAccessory,
  PlatformConfig,
  Service,
  Characteristic,
} from 'homebridge';

import { PLUGIN_NAME, PLATFORM_NAME } from './settings.js';
import { SwiftBridge } from './websocket.js';
import { EqivaLockAccessory } from './eqivaLockAccessory.js';

export class HomebridgeEqivaSwiftBridgePlatform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service;
  public readonly Characteristic: typeof Characteristic;

  private readonly accessories: PlatformAccessory[] = [];
  private swift: SwiftBridge;

  constructor(
    public readonly log: Logging,
    public readonly config: PlatformConfig,
    public readonly api: API,
  ) {
    this.Service = api.hap.Service;
    this.Characteristic = api.hap.Characteristic;

    const port = this.config.wsPort ?? 9099;
    this.swift = new SwiftBridge(log, port);

    this.swift.on('listening', () => {
      this.log.info(`WebSocket bridge started on port ${port}`);
    });

    // Homebridge lifecycle
    this.api.on('didFinishLaunching', () => {
      this.log.debug('didFinishLaunching – registering accessory');
      this.addOrRestoreAccessory();
    });
  }

  // Called for every accessory restored from cache
  configureAccessory(accessory: PlatformAccessory): void {
    this.log.info('Restoring accessory from cache:', accessory.displayName);
    this.accessories.push(accessory);
  }

  // --------------------------------------------------------------------------

  private addOrRestoreAccessory(): void {
    const uuid = this.api.hap.uuid.generate('eqiva-lock-accessory');
    let accessory = this.accessories.find(acc => acc.UUID === uuid);

    if (!accessory) {
      this.log.info('Adding new accessory');
      accessory = new this.api.platformAccessory(this.config.accessoryName, uuid);
      this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
      this.accessories.push(accessory);
    }

    // Instantiate our wrapper (this does idempotent service creation).
    new EqivaLockAccessory(this, accessory, this.swift);
  }
}
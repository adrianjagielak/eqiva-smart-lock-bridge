import { WebSocketServer, WebSocket } from 'ws';
import { EventEmitter } from 'events';
import { StatusMessage } from './types.js';
import { Logging } from 'homebridge';

type Command = 'lock' | 'unlock' | 'open';

/**
 * SwiftBridge wraps a bare WebSocketServer and turns it into an EventEmitter
 * that speaks in domain events: 'status' and 'connected'.
 */
export class SwiftBridge extends EventEmitter {
  private swift?: WebSocket;
  private queuedCommand?: Command;

  constructor(
    public readonly log: Logging,
    port: number,
  ) {
    super();
    const wss = new WebSocketServer({ port });
    wss.on('connection', (socket) => this.handleConnection(socket));
    wss.on('listening', () => {
      this.emit('listening', port);
      this.log.info(`WebSocket listening on :${port}`);
    });
  }

  /** Send a command to the Swift app (or queue if not connected). */
  public send(cmd: Command): void {
    if (this.swift && this.swift.readyState === WebSocket.OPEN) {
      this.swift.send(cmd);
    } else {
      this.log.warn('Swift not connected – queueing', cmd);
      this.queuedCommand = cmd;
    }
  }

  // --------------------------------------------------------------------------

  private handleConnection(socket: WebSocket): void {
    this.log.info('Swift connected');
    this.swift = socket;
    this.emit('connected');

    // Flush queued command
    if (this.queuedCommand) {
      const cmd = this.queuedCommand;
      this.queuedCommand = undefined;
      this.send(cmd);
    }

    socket.on('message', (data) => {
      try {
        const msg: StatusMessage = JSON.parse(data.toString());
        this.emit('status', msg);
      } catch (e) {
        this.log.error('Bad WS payload', e);
      }
    });

    socket.on('close', () => {
      this.log.warn('Swift disconnected');
      this.swift = undefined;
    });
  }
}
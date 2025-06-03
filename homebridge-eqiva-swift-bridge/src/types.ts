export enum SwiftLockState {
  unknownProbablyJammed = 'unknownProbablyJammed',
  moving                = 'moving',
  unlocked              = 'unlocked',
  locked                = 'locked',
  opened                = 'opened',
  trulyUnkonwn          = 'trulyUnkonwn',
}

export interface StatusMessage {
  state: SwiftLockState;
  batteryLow: boolean;
}
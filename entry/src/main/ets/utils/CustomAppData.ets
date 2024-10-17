import { common } from '@kit.AbilityKit';

@ObservedV2
export class AppRuntimeInfo {
  @Trace appBottomAvoidHeight: number = 0;
  @Trace appTopAvoidHeight: number = 0;
  @Trace appContext?: common.UIAbilityContext;
  @Trace appConfigs: Array<TokenConfig> = [];
}

export enum otpType {
  TOTP,
  Forti,
  HOTP,
  Steam
}

export class TokenConfig {
  TokenType: otpType;
  TokenKey: string;
  TokenHost: string;
  TokenUser: string;
  TokenAlgorithm: string;
  TokenPeriod: number;
  TokenDigits: number;
  TokenCounter: number;
  FortiToken: string;
  FortiDevID: string;

  constructor(
    key: string = '',
    type: number = 0,
    host: string = 'Unknown',
    user: string = 'Unknown',
    alg: string = 'SHA1',
    period: number = 30,
    digits: number = 6,
    counter: number = 0
  ) {
    this.TokenKey = key;
    this.TokenType = type;
    this.TokenHost = host;
    this.TokenUser = user;
    this.TokenAlgorithm = alg;
    this.TokenPeriod = period;
    this.TokenDigits = digits;
    this.TokenCounter = counter;
    this.FortiToken = '';
    this.FortiDevID = '';
  }

}
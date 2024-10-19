import { common } from '@kit.AbilityKit';
import { HMACAlgorithm, getIconPathByIssuer } from './TokenUtils';

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
  TokenSecret: string;
  TokenIssuer: string;
  TokenName: string;
  TokenAlgorithm: HMACAlgorithm;
  TokenPeriod: number;
  TokenDigits: number;
  TokenCounter: number;
  FortiToken: string;
  FortiDevID: string;
  TokenIcon: string;

  constructor(
    secret: string = '',
    type: otpType = 0,
    issuer: string = 'Unknown',
    name: string = 'Unknown',
    algorithm: HMACAlgorithm = 'SHA1',
    period: number = 30,
    digits: number = 6,
    counter: number = 0
  ) {
    this.TokenSecret = secret;
    this.TokenType = type;
    this.TokenIssuer = issuer;
    this.TokenName = name;
    this.TokenAlgorithm = algorithm;
    this.TokenPeriod = period;
    this.TokenDigits = digits;
    this.TokenCounter = counter;
    this.FortiToken = '';
    this.FortiDevID = '';
    this.TokenIcon = getIconPathByIssuer(issuer);
  }
}
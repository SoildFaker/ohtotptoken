import { HMACAlgorithm, getIconPathByIssuer } from './TokenUtils';
import { util } from '@kit.ArkTS';
import { maFile } from './SteamUtils';

export enum otpType {
  TOTP,
  Forti,
  HOTP,
  Steam
}

export class TokenConfig {
  TokenUUID: string;
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
  RankScore: number;
  SteamMaFile: maFile | undefined = undefined;

  constructor(
    secret: string = '',
    type: otpType = 0,
    issuer: string = 'Unknown',
    name: string = 'Unknown',
    algorithm: HMACAlgorithm = 'SHA1',
    period: number = 30,
    digits: number = 6,
    counter: number = 0,
    rank: number = 0
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
    this.TokenUUID = util.generateRandomUUID();
    this.TokenIcon = getIconPathByIssuer(issuer);
    this.RankScore = rank;
  }

}
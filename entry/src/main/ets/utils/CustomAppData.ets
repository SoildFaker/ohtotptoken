import { common } from '@kit.AbilityKit';
import { distributedKVStore } from '@kit.ArkData';

@ObservedV2
export class AppRuntimeInfo {
  @Trace appBottomAvoidHeight: number = 0;
  @Trace appTopAvoidHeight: number = 0;
  @Trace appContext?: common.UIAbilityContext;
}

export class TokenConfig {
  TokenType: number
  TokenKey: string
  TokenHost: string
  TokenUser: string
  TokenAlgorithm: string
  TokenPeriod: number
  TokenDigits: number
  FortiToken: string
  FortiDevID: string

  constructor(
    key: string = 'EEAEVVEYZSERRHEM',
    type: number = 0,
    host: string = 'Unknown',
    user: string = 'Unknown',
    alg: string = 'SHA1',
    period: number = 30,
    digits: number = 6
  ) {
    this.TokenKey = key
    this.TokenType = type
    this.TokenHost = host
    this.TokenUser = user
    this.TokenAlgorithm = alg
    this.TokenPeriod = period
    this.TokenDigits = digits
    this.FortiToken = ''
    this.FortiDevID = ''
  }

}
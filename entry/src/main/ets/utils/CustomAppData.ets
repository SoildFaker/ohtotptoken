import { common } from '@kit.AbilityKit';
import { distributedKVStore } from '@kit.ArkData';

@ObservedV2
export class AppRuntimeInfo {
  @Trace appBottomAvoidHeight: number = 0;
  @Trace appTopAvoidHeight: number = 0;
  @Trace appContext?: common.UIAbilityContext;
}

export class TokenConfig {
  TokenKey: string
  TokenHost: string
  TokenUser: string
  TokenAlgorithm: string
  TokenPeriod: number
  TokenDigits: number

  constructor(key: string = '0000', host: string = 'Unknown', user: string = 'Unknown', alg: string = 'SHA1', period: number = 30, digits: number = 6) {
    this.TokenKey = key
    this.TokenHost = host
    this.TokenUser = user
    this.TokenAlgorithm = alg
    this.TokenPeriod = period
    this.TokenDigits = digits
  }

}
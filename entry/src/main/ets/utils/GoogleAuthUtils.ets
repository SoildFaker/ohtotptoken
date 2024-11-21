import { decode_google_auth_pb } from "libotpcutils.so";
import { otpType, TokenConfig } from "./TokenConfig";
import { JSON } from "@kit.ArkTS";
import { getIconPathByIssuer, HMACAlgorithm } from "./TokenUtils";

enum GA_Algorithm {
  ALGORITHM_UNSPECIFIED = 0,
  SHA1 = 1,
  SHA256 = 2,
  SHA512 = 3,
  MD5 = 4,
}

enum GA_DigitCount {
  DIGIT_COUNT_UNSPECIFIED = 0,
  SIX = 1,
  EIGHT = 2,
  SEVEN = 3,
}

enum GA_OtpType {
  OTP_TYPE_UNSPECIFIED = 0,
  HOTP = 1,
  TOTP = 2,
}

class GoogleAuth {
   public secret: string = '';
   public name: string = '';
   public issuer: string = '';
   public algorithm: GA_Algorithm = GA_Algorithm.SHA1;
   public digits: GA_DigitCount = GA_DigitCount.SIX;
   public type: GA_OtpType = GA_OtpType.TOTP;
   public counter: number = 30;
}

const GA_ALG_MAP: Map<GA_Algorithm, HMACAlgorithm> = new Map([
  [GA_Algorithm.ALGORITHM_UNSPECIFIED, 'SHA1' as HMACAlgorithm],
  [GA_Algorithm.SHA1, 'SHA1' as HMACAlgorithm],
  [GA_Algorithm.SHA256, 'SHA256' as HMACAlgorithm],
  [GA_Algorithm.SHA512, 'SHA512' as HMACAlgorithm],
  [GA_Algorithm.MD5, 'MD5' as HMACAlgorithm],
]);

const GA_TYPE_MAP: Map<GA_OtpType, otpType> = new Map([
  [GA_OtpType.OTP_TYPE_UNSPECIFIED, otpType.TOTP],
  [GA_OtpType.TOTP, otpType.TOTP],
  [GA_OtpType.HOTP, otpType.HOTP],
]);

const GA_DIGIT_MAP: Map<GA_DigitCount, number> = new Map([
  [GA_DigitCount.DIGIT_COUNT_UNSPECIFIED, 6],
  [GA_DigitCount.SIX, 6],
  [GA_DigitCount.EIGHT, 8],
  [GA_DigitCount.SEVEN, 7],
]);

export async function decodeProtobuf(payload: string): Promise<Array<TokenConfig>> {
  const google_auth_json = decode_google_auth_pb(payload);
  const GAs = JSON.parse(google_auth_json) as Array<GoogleAuth>;

  let result: Array<TokenConfig> = [];
  GAs.forEach((ga) => {
    let token = new TokenConfig();
    token.TokenType = GA_TYPE_MAP.get(ga.type) ?? otpType.TOTP;
    token.TokenSecret = ga.secret;
    token.TokenIssuer = ga.issuer;
    token.TokenName = ga.name;
    token.TokenAlgorithm = GA_ALG_MAP.get(ga.algorithm) ?? 'SHA1';
    token.TokenPeriod = 30;
    token.TokenCounter = ga.counter;
    token.TokenDigits = GA_DIGIT_MAP.get(ga.digits) ?? 6;
    token.TokenIcon = getIconPathByIssuer(token.TokenIssuer);
    result.push(token)
  });

  return result;
}
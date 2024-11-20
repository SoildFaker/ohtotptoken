import { http } from "@kit.NetworkKit";
import { BusinessError } from "@kit.BasicServicesKit";

export class maFile {
  public shared_secret: string = '';
  public serial_number: string = '';
  public revocation_code: string = '';
  public uri: string = '';
  public server_time: number = 0;
  public account_name: string = '';
  public token_gid: string = '';
  public identity_secret: string = '';
  public secret_1: string = '';
  public status: number = 0;
  public device_id: string = '';
  public fully_enrolled: boolean = false;
  public Session: string | null = null;
}

export enum ESessionPersistence {
  k_ESessionPersistence_Invalid = -1,
  k_ESessionPersistence_Ephemeral = 0,
  k_ESessionPersistence_Persistent = 1,
}

class SteamAPI {
  private static steam_api_url: string = 'https://api.steampowered.com';

  public static UpdateAuthSessionWithMobileConfirmation(version: number, client_id: number, steamid: number, signature: string, confirm: boolean, persistence: ESessionPersistence): void {
    const api_url_base = SteamAPI.steam_api_url + '/IAuthenticationService/UpdateAuthSessionWithMobileConfirmation/v1/';
    let httpRequest = http.createHttp();

    httpRequest.request(
      api_url_base,
      {
        method: http.RequestMethod.POST,
        extraData: { 'version': version, 'client_id': client_id, 'steamid': steamid, 'signature': signature, 'confirm': confirm, 'persistence': persistence},
        header: { 'Accept' : 'application/json' },
        readTimeout: 60000,
        connectTimeout: 60000,
        usingProtocol: http.HttpProtocol.HTTP1_1,
        usingProxy: false,
      },
      (err: BusinessError, data: http.HttpResponse) => {
        let tmp = data;
        if (!err) {

        } else {

        }
        httpRequest.destroy();
      });
  }
}

export class SteamUtils {
  private static steam_chars: string = "23456789BCDFGHJKMNPQRTVWXY";
  private static steam_digits: number = 5;

  public static SteamTokenFromTOTP(totp_token: number): string {
    let total_chars = SteamUtils.steam_chars.length;
    let int_code = totp_token;
    let steam_token = '';
    for (let index = 0; index < SteamUtils.steam_digits; index++) {
      let pos = int_code % total_chars;
      steam_token += SteamUtils.steam_chars[pos];
      int_code = Math.floor(int_code / total_chars);
    }
    return steam_token;
  }

  public static LoginWithQR(url: string): void {
  }

}
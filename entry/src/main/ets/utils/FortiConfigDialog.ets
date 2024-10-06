import { TokenConfig } from '../utils/CustomAppData';
import { base32Decode, base32Encode, stringToIntArray } from '../utils/TokenUtils'
import { scanCore, scanBarcode } from '@kit.ScanKit';
import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer, util } from '@kit.ArkTS';
import promptAction from '@ohos.promptAction'

//"{\"d\":{\"__type\":\"SoftToken.MobileProvisionResponse\",\"__version\":\"\",\"__device_version\":\"\",\"__device_build\":\"\",\"mobile_id_hash\":\"\",\"seed\":\"\",\"token\":\"\",\"image_file\":\"\",\"pin_required\":\"\",\"pin_require_type\":\"\",\"pin_length\":0,\"counter\":0,\"encryption_key\":\"\",\"issuer\":\"\",\"result\":0,\"error\":{\"error_code\":40,\"error_message\":\"FTM token Activation Code is invalid\"}}}"
class forti_server_resp_err {
  error_code?: string
  error_message?: string
}

class  forti_server_resp_data {
  seed?: string
  issuer?: string
  error?: forti_server_resp_err
}
class  forti_server_resp {
  d!: forti_server_resp_data
}

@Preview
@CustomDialog
export struct FortiConfigDialog {
  controller?: CustomDialogController
  @Prop conf_json?: string = ''
  @State conf: TokenConfig = new TokenConfig('', 1)
  @State btn_camera_clicked: number = 0
  @State btn_dev_id_clicked: number = 0
  @State warn_dev_id_popup: boolean = false
  @State btn_wait_from_forti: boolean = false

  private cache_dir: string = getContext(this).cacheDir;

  cancel?: () => void

  confirm: (new_conf: string) => void = () => {
  }

  aboutToAppear(): void {
    if (this.conf_json != undefined && this.conf_json.length > 0) {
      this.conf = JSON.parse(this.conf_json!)
    } else {
      this.getRandDevID()
    }
  }

  getRandDevID(): void {
    this.conf.FortiDevID = buffer.from(util.generateRandomBinaryUUID()).toString('hex').slice(0, 16)
    this.conf.TokenHost = 'Forti'
    this.conf.TokenPeriod = 60
  }

  decrypt_seed(seed: string) {
    let aes_decoder = cryptoFramework.createCipher('AES128|CBC|NoPadding');
    let aes_iv: cryptoFramework.IvParamsSpec = {
      algName: "IvParamsSpec",
      iv: {data: stringToIntArray('fortitokenmobile')}
    };
    let symKeyBlob: cryptoFramework.DataBlob = { data: stringToIntArray(this.conf.FortiDevID) };
    let aesGenerator = cryptoFramework.createSymKeyGenerator('AES128');
    let aes_key = aesGenerator.convertKeySync(symKeyBlob);
    aes_decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, aes_key, aes_iv);
    let base64 = new util.Base64Helper();
    try {
      let b64seed = base64.decodeSync(seed)
      setTimeout(() => {
        aes_decoder.doFinal({data: b64seed}).then((decryptData) => {
          let decoder = new util.TextDecoder()
          let decode_hex = decoder.decodeToString(decryptData.data.slice(0, 40))
          this.conf.TokenKey = base32Encode(buffer.from(decode_hex, 'hex').buffer as Uint8Array)
          this.btn_wait_from_forti = false;
        });
      }, 1000)
    } catch (err) {
      this.btn_wait_from_forti = false;
      promptAction.showToast({message: `Error: ${err.message}`})
    }
  }

  requestKeyFromForti(): void {
    if (this.conf.FortiToken.length !== 16) {
      promptAction.showToast({ message: 'ERROR: Wrong Forti Token!' })
      return;
    }
    if (this.conf.FortiDevID.length !== 16) {
      promptAction.showToast({ message: 'ERROR: Wrong Device ID!' })
      return;
    }
    let raw_token = base32Decode(this.conf.FortiToken)
    if (!(raw_token[0] === 0x21)) {
      promptAction.showToast({ message: 'ERROR: Wrong User Token!' })
      return;
    }
    this.btn_wait_from_forti = true;
    raw_token = raw_token.slice(2)
    let raw_token_hex = buffer.from(raw_token).toString('hex')// Array.from(raw_token, byte => byte.toString(16).padStart(2, '0')).join('')
    let httpRequest = http.createHttp();
    httpRequest.on('headersReceive', (header: Object) => {
      console.info('header: ' + JSON.stringify(header));
    })

    let cer_path = this.cache_dir + "/fmt.ks"

    httpRequest.request(
      "https://globalftm.fortinet.net/SoftToken/Provisioning.asmx/Mobile",
      {
        method: http.RequestMethod.POST,
        extraData: {'d': {'mobile_id': this.conf.FortiDevID, '__type': 'SoftToken.MobileProvisionRequest', 'token_activation_code': raw_token_hex}},
        header: { 'Accept' : 'application/json' },
        readTimeout: 60000,
        connectTimeout: 60000,
        usingProtocol: http.HttpProtocol.HTTP1_1,
        usingProxy: false,
        clientCert: {
          certPath: cer_path,
          keyPath: '',
          certType: http.CertType.P12,
          keyPassword: "Terran2023"
        },
      },
      (err: BusinessError, data: http.HttpResponse) => {
        if (!err) {
          console.log(JSON.stringify(data.result))
          let resp: forti_server_resp = JSON.parse(data.result.toString())

          if (resp.d.error != undefined) {
            this.btn_wait_from_forti = false;
            console.error(`${resp.d.error.error_message}, code ${resp.d.error.error_code}`)
            promptAction.showToast({ message: `${resp.d.error.error_message}, code ${resp.d.error.error_code}` })
          } else {
            this.decrypt_seed(resp.d.seed!)
            this.conf.TokenUser = resp.d.issuer!
          }
          httpRequest.off('headersReceive');
          httpRequest.destroy();
        } else {
          this.btn_wait_from_forti = false;
          console.info('error:' + JSON.stringify(err));
          httpRequest.off('headersReceive');
          httpRequest.destroy();
        }
      });

  }

  build() {
    Column({ space: 10 }) {
      Row() {

      }
      .height(10)
      Row() {
        Text($r('app.string.tab_token_add_forti_key'))
          .fontSize(30)
          .fontWeight(FontWeight.Bold)
        SymbolGlyph($r('sys.symbol.camera'))
          .fontSize(30)
          .fontColor([$r('app.color.item_fg')])
          .fontWeight(FontWeight.Medium)
          .symbolEffect(new BounceSymbolEffect(EffectScope.WHOLE, EffectDirection.UP),
            this.btn_camera_clicked)
          .onClick(() => {
            this.btn_camera_clicked++
            let options: scanBarcode.ScanOptions = {
              scanTypes: [scanCore.ScanType.ALL],
              enableMultiMode: true,
              enableAlbum: true
            };
            scanBarcode.startScanForResult(getContext(this), options).then((result: scanBarcode.ScanResult) => {
              this.conf.FortiToken = result.originalValue
              hilog.info(0x0001, '[Scan CPSample]', `Succeeded in getting ScanResult by promise with options, result is ${JSON.stringify(result)}`);
            }).catch((error: BusinessError) => {
              hilog.error(0x0001, '[Scan CPSample]',
                `Failed to get ScanResult by promise with options. Code:${error.code}, message: ${error.message}`);
            });
          })
      }
      .width('100%')
      .justifyContent(FlexAlign.SpaceBetween)
      Row(){

      }
      .width('100%')
      .borderRadius(1)
      .backgroundColor($r('app.color.item_fg'))
      .height(2)
      Column({ space: 10 }) {
        Row() {
          Text($r('app.string.dialog_cfg_forti_token'))
            .width('30%')
          TextInput({ text: this.conf.FortiToken, placeholder: this.conf.FortiToken })
            .onChange((value) => {
              this.conf.FortiToken = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Row() {
            Text($r('app.string.dialog_cfg_forti_dev_id'))
            SymbolGlyph($r('sys.symbol.exclamationmark_circle'))
              .fontColor([Color.Red])
              .margin({right: 10})
              .bindPopup(this.warn_dev_id_popup, {
                message: getContext(this).resourceManager.getStringSync($r('app.string.warn_forti_dev_id_popup')).toString(),
                onStateChange: (e)=> {
                  if (!e.isVisible) {
                    this.warn_dev_id_popup = false
                  }
                }
              })

          }
          .onClick(() => {
            this.warn_dev_id_popup = !this.warn_dev_id_popup;
          })
          .width('30%')
          .justifyContent(FlexAlign.SpaceBetween)
          Stack() {
            Row() {
              SymbolGlyph($r('sys.symbol.arrow_counterclockwise'))
                .margin({ right: 10 })
                .fontSize(20)
                .symbolEffect(new BounceSymbolEffect(EffectScope.WHOLE, EffectDirection.UP),
                  this.btn_dev_id_clicked)
            }
            .onClick(() => {
              this.btn_dev_id_clicked++
              this.getRandDevID()
            })
            .zIndex(2)
            .height(30)
            TextInput({ text: this.conf.FortiDevID, placeholder: this.conf.FortiDevID })
              .onChange((value) => {
                this.conf.FortiDevID = value
              })
              .zIndex(1)
              .width('70%')
          }
          .alignContent(Alignment.End)
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Stack() {
            Button($r('app.string.dialog_cfg_forti_btn_gen_key'))
              .onClick(() => {
                this.requestKeyFromForti()
              })
              .enabled(!this.btn_wait_from_forti)
              .backgroundColor($r("app.color.item_bg"))
              .fontColor($r('app.color.str_main'))
              .border({ width: 1 })
              .width('100%')
            LoadingProgress()
              .height(30)
              .visibility(this.btn_wait_from_forti ? Visibility.Visible : Visibility.Hidden)
          }
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r('app.string.dialog_cfg_tk_key'))
            .width('30%')
          TextInput({ text: this.conf.TokenKey, placeholder: this.conf.TokenKey })
            .onChange((value) => {
              this.conf.TokenKey = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)

        Row() {
          Text($r('app.string.dialog_cfg_tk_user'))
            .width('30%')
          TextInput({ text: this.conf.TokenUser, placeholder: this.conf.TokenUser })
            .onChange((value) => {
              this.conf.TokenUser = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
      }
      .padding({left: 10, right: 10})

      .width('100%')

      Flex({ justifyContent: FlexAlign.SpaceAround }) {
        Button($r('app.string.dialog_btn_cancel'))
          .fontColor($r('app.color.item_fg'))
          .backgroundColor(Color.Transparent)
          .onClick(() => {
            if (this.controller != undefined) {
              this.controller.close()
            }
          })
          .width('100%')
        Button($r('app.string.dialog_btn_confirm'))
          .fontColor(Color.Red)
          .backgroundColor(Color.Transparent)
          .onClick(() => {
            if (this.conf.TokenKey.length > 0) {
              if (this.controller != undefined) {
                this.confirm(JSON.stringify(this.conf))
                this.controller.close()
              }
            } else {
              promptAction.showToast({ message: 'Enter a correct key' })
            }
          })
          .width('100%')

      }
    }
    .padding(10)
    .width('100%')
  }
}
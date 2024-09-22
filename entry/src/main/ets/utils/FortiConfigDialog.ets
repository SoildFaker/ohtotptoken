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
  @State forti_token: string = 'EEAEVVEYZSERRHEM'
  @State forti_dev_id: string = 'e248e1e9527f20ff'

  private cache_dir: string = getContext(this).cacheDir;

  cancel?: () => void

  confirm: (new_conf: string) => void = () => {
  }

  aboutToAppear(): void {
    if (this.conf_json != undefined && this.conf_json.length > 0) {
      this.conf = JSON.parse(this.conf_json!)
    }
  }


  decrypt_seed(seed: string): string {
    let aes_decoder = cryptoFramework.createCipher('AES128|CBC|PKCS7');
    let aes_iv: cryptoFramework.IvParamsSpec = {
      algName: "IvParamsSpec",
      iv: {data: stringToIntArray('fortitokenmobile')}
    };
    let symKeyBlob: cryptoFramework.DataBlob = { data: stringToIntArray(this.forti_dev_id) };
    let aesGenerator = cryptoFramework.createSymKeyGenerator('AES128');
    let aes_key = aesGenerator.convertKeySync(symKeyBlob);
    aes_decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, aes_key, aes_iv);
    let base64 = new util.Base64Helper();
    let decryptData = aes_decoder.doFinalSync({data: base64.decodeSync(seed)});
    return decryptData.data.slice(0, 40).toString()
  }

  requestKeyFromForti(): void {
    let raw_token = base32Decode(this.forti_token)
    let valid_prefix: number[] = [0x21, 0x00]
    if (!raw_token.slice(0, 2).every((byte, index) => byte == valid_prefix[index])) {
      promptAction.showToast({ message: 'ERROR: wrong User Token!' })
      return;
    }
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
        extraData: {'d': {'mobile_id': this.forti_dev_id, '__type': 'SoftToken.MobileProvisionRequest', 'token_activation_code': raw_token_hex}},
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
            console.error(`${resp.d.error.error_message}, code ${resp.d.error.error_code}`)
            promptAction.showToast({ message: `${resp.d.error.error_message}, code ${resp.d.error.error_code}` })
          } else {
            this.conf.TokenKey = this.decrypt_seed(resp.d.seed!)
            this.conf.TokenUser = resp.d.issuer!
          }
          httpRequest.off('headersReceive');
          httpRequest.destroy();
        } else {
          console.info('error:' + JSON.stringify(err));
          httpRequest.off('headersReceive');
          httpRequest.destroy();
        }
      });
  }

  addNewConfigOTP(uri: string): void {

  }

  build() {
    Column({ space: 10 }) {
      Row() {

      }
      .height(10)
      Row() {
        Text("Forti Config")
          .fontSize(30)
          .fontWeight(FontWeight.Bold)
        SymbolGlyph($r('sys.symbol.camera'))
          .fontSize(30)
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
              this.forti_token = result.originalValue
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
      .backgroundColor(Color.Black)
      .height(2)
      Column({ space: 10 }) {
        Row() {
          Text($r('app.string.dialog_cfg_forti_token'))
          TextInput({ text: this.forti_token, placeholder: this.forti_token })
            .onChange((value) => {
              this.forti_token = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r('app.string.dialog_cfg_forti_dev_id'))
          TextInput({ text: this.forti_dev_id, placeholder: this.forti_dev_id })
            .onChange((value) => {
              this.forti_dev_id = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Button($r('app.string.dialog_cfg_forti_btn_gen_key'))
            .onClick(() => {
              this.requestKeyFromForti()
            })
            .backgroundColor(Color.White)
            .fontColor(Color.Black)
            .border({ width: 1 })
            .width('100%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r('app.string.dialog_cfg_tk_key'))
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
          .fontColor(Color.Black)
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
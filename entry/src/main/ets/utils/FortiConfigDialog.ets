import { AppRuntimeInfo, TokenConfig } from '../utils/CustomAppData';
import { scanCore, scanBarcode } from '@kit.ScanKit';
import { url } from '@kit.ArkTS';
import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

@Preview
@CustomDialog
export struct FortiConfigDialog {
  controller?: CustomDialogController
  @Prop conf_json?: string = ''
  @State conf: TokenConfig = new TokenConfig('', 1)
  @State btn_camera_clicked: number = 0
  @State forti_token: string = 'EEAEVVEYZSERRHEM'
  @State forti_dev_id: string = 'e248e1e9527f20ff'

  private filesDir: string = getContext(this).filesDir;

  cancel?: () => void

  confirm: (new_conf: string) => void = () => {
  }

  aboutToAppear(): void {
    if (this.conf_json != undefined && this.conf_json.length > 0) {
      this.conf = JSON.parse(this.conf_json!)
    }
  }

  requestKeyFromForti(): void {
    let httpRequest = http.createHttp();
    httpRequest.on('headersReceive', (header: Object) => {
      console.info('header: ' + JSON.stringify(header));
    })

    httpRequest.request(
      "https://globalftm.fortinet.net/SoftToken/Provisioning.asmx/Mobile",
      {
        method: http.RequestMethod.POST,
        extraData: 'd=1',
        header: { 'Accept' : 'application/json' },
        readTimeout: 60000,
        connectTimeout: 60000,
        usingProtocol: http.HttpProtocol.HTTP1_1,
        usingProxy: false,
        clientCert: {
          certPath: 'resource://rawfile/ftm.ks',
          keyPath: '',
          certType: http.CertType.P12,
          keyPassword: "Terran2023"
        },
      },
      (err: BusinessError, data: http.HttpResponse) => {
        if (!err) {
          // data.result为HTTP响应内容，可根据业务需要进行解析
          console.info('Result:' + JSON.stringify(data.result));
          console.info('code:' + JSON.stringify(data.responseCode));
          console.info('type:' + JSON.stringify(data.resultType));
          // data.header为HTTP响应头，可根据业务需要进行解析
          console.info('header:' + JSON.stringify(data.header));
          console.info('cookies:' + JSON.stringify(data.cookies)); // 自API version 8开始支持cookie
          // 取消订阅HTTP响应头事件
          httpRequest.off('headersReceive');
          // 当该请求使用完毕时，开发者务必调用destroy方法主动销毁该JavaScript Object。
          httpRequest.destroy();
        } else {
          console.info('error:' + JSON.stringify(err));
          // 取消订阅HTTP响应头事件
          httpRequest.off('headersReceive');
          // 当该请求使用完毕时，开发者务必调用destroy方法主动销毁该JavaScript Object。
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
            if (this.controller != undefined) {
              this.confirm(JSON.stringify(this.conf))
              this.controller.close()
            }
          })
          .width('100%')

      }
    }
    .padding(10)
    .width('100%')
  }
}
import { TokenConfig } from '../utils/CustomAppData';
import { scanCore, scanBarcode } from '@kit.ScanKit';
import { url } from '@kit.ArkTS';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { HMACAlgorithm } from './TokenUtils';
import { SelectOptions } from '@kit.ArkUI';

@Preview
@CustomDialog
export struct HOTPConfigDialog {
  controller?: CustomDialogController;
  @Prop conf_json?: string = '';
  @State conf: TokenConfig = new TokenConfig('', 2);
  @State btn_camera_clicked: number = 0;

  cancel?: () => void;
  confirm: (new_conf: string) => void = () => {};

  aboutToAppear(): void {
    if (this.conf_json != undefined && this.conf_json.length > 0) {
      this.conf = JSON.parse(this.conf_json!);
    }
  }

  addNewConfigOTP(uri: string): void {
    let otp_url: url.URL
    try {
      otp_url = url.URL.parseURL(uri)
    } catch (error) {
      console.error('Invalid OTPAuth URL:', error);
      return;
    }

    if (otp_url.protocol !== 'otpauth:') {
      console.error('Invalid protocol');
      return;
    }

    const type = otp_url.host;
    if (type.toLowerCase() !== 'hotp') {
      console.error('Invalid type');
      return;
    }
    const pathParts = otp_url.pathname.slice(1).split('/');
    const labelParts = decodeURIComponent(pathParts[0]).split(':');
    this.conf.TokenIssuer = labelParts[0];
    this.conf.TokenName = labelParts[1];

    const parameters: Record<string, string> = {};
    const query = otp_url.href.split('?')[1];
    if (query) {
      query.split('&').forEach(part => {
        const kv: string[] = part.split('=');
        parameters[kv[0]] = kv[1];
      });
    }
    this.conf.TokenSecret = parameters['secret'];
    this.conf.TokenPeriod = parseInt(parameters['counter'] ?? '0');
    this.conf.TokenDigits = parseInt(parameters['digits'] ?? '6');
  }

  build() {
    Column({ space: 10 }) {
      Row() {

      }
      .height(10)
      Row() {
        Text($r('app.string.tab_token_add_hotp_key'))
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
              this.addNewConfigOTP(result.originalValue)
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
          Text($r("app.string.dialog_cfg_tk_secret"))
            .width('30%')
          TextInput({ text: this.conf.TokenSecret, placeholder: this.conf.TokenSecret })
            .onChange((value) => {
              this.conf.TokenSecret = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r("app.string.dialog_cfg_tk_issuer"))
            .width('30%')
          TextInput({ text: this.conf.TokenIssuer, placeholder: this.conf.TokenIssuer })
            .onChange((value) => {
              this.conf.TokenIssuer = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r("app.string.dialog_cfg_tk_name"))
            .width('30%')
          TextInput({ text: this.conf.TokenName, placeholder: this.conf.TokenName })
            .onChange((value) => {
              this.conf.TokenName = value
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r('app.string.dialog_cfg_tk_alg'))
            .width('30%')
          Select([
            {value: 'SHA1'},
            {value: 'SHA224'},
            {value: 'SHA256'},
            {value: 'SHA384'},
            {value: 'SHA512'},
            {value: 'SM3'},
            {value: 'MD5'},
          ])
            .value(this.conf.TokenAlgorithm)
            .onSelect((_, value) => {
              this.conf.TokenAlgorithm = value as HMACAlgorithm
            })
            .width('70%')
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r('app.string.dialog_cfg_tk_digits'))
            .width('30%')
          Row() {
            Text("4")
            Radio({ value: '4', group: 'rg_cfg_digits' }).checked(this.conf.TokenDigits === 4)
              .radioStyle({
                checkedBackgroundColor: Color.Blue
              })
              .onChange((isChecked: boolean) => {
                if (isChecked) {
                  this.conf.TokenDigits = 4
                }
              })
            Text("6")
            Radio({ value: '6', group: 'rg_cfg_digits' }).checked(this.conf.TokenDigits === 6)
              .radioStyle({
                checkedBackgroundColor: Color.Blue
              })
              .onChange((isChecked: boolean) => {
                if (isChecked) {
                  this.conf.TokenDigits = 6
                }
              })
            Text("8")
            Radio({ value: '8', group: 'rg_cfg_digits' }).checked(this.conf.TokenDigits === 8)
              .radioStyle({
                checkedBackgroundColor: Color.Blue
              })
              .onChange((isChecked: boolean) => {
                if (isChecked) {
                  this.conf.TokenDigits = 8
                }
              })
          }
          .width('70%')
          .justifyContent(FlexAlign.SpaceEvenly)
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        Row() {
          Text($r('app.string.dialog_cfg_tk_counter'))
            .width('30%')
          TextInput({ text: this.conf.TokenCounter.toString(), placeholder: this.conf.TokenCounter.toString() })
            .onChange((value) => {
              let counter = parseInt(value);
              this.conf.TokenCounter = isNaN(counter) ? 0 : counter;
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

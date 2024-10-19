import { TokenConfig } from '../utils/CustomAppData';
import { scanCore, scanBarcode } from '@kit.ScanKit';
import { url } from '@kit.ArkTS';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { getIconPathByIssuer } from './TokenUtils';

@Preview
@CustomDialog
export struct SteamConfigDialog {
  controller?: CustomDialogController;
  @Prop conf_json?: string = '';
  @State conf: TokenConfig = new TokenConfig('', 3, 'Steam', 'User', 'SHA1', 30, 10);
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
    if (type.toLowerCase() !== 'totp') {
      console.error('Invalid type');
      return;
    }
    const pathParts = otp_url.pathname.slice(1).split('/');
    const labelParts = decodeURIComponent(pathParts[0]).split(':');
    this.conf.TokenIssuer=labelParts[0];
    this.conf.TokenIcon=getIconPathByIssuer(labelParts[0])
    this.conf.TokenName = labelParts[1];

    const parameters: Record<string, string> = {};
    const query = otp_url.href.split('?')[1].toLowerCase();
    if (query) {
      query.split('&').forEach(part => {
        const kv: string[] = part.split('=');
        parameters[kv[0]] = kv[1];
      });
    }
    this.conf.TokenSecret = parameters['secret'];
    this.conf.TokenPeriod = parseInt(parameters['period'] ?? '30');
    this.conf.TokenDigits = parseInt(parameters['digits'] ?? '10');
  }

  build() {
    Column({ space: 10 }) {
      Row() {

      }
      .height(10)
      Row() {
        Text($r('app.string.tab_token_add_stream_key'))
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
              this.conf.TokenIssuer=value;
              this.conf.TokenIcon=getIconPathByIssuer(value);
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

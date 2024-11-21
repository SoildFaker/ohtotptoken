import { systemDateTime } from '@kit.BasicServicesKit';
import { otpType, TokenConfig } from '../utils/TokenConfig';
import { generateOTP } from '../utils/TokenUtils';
import { TokenIcon } from './TokenIcon';
import { pasteboard } from '@kit.BasicServicesKit';
import { promptAction } from '@kit.ArkUI';
import { SteamUtils } from '../utils/SteamUtils';

let last_token_hide = true;

@Preview
@ComponentV2
export struct TokenItem {
  @Require @Param Config: TokenConfig = new TokenConfig();
  @Require @Param TokenHideEnable: boolean = false;
  @Event Update: (conf: TokenConfig) => void = () => {};

  @Local TokenNumber: string = '000000';
  @Local TokenCounter: string = '0';
  @Local TokenLeftPeriod: number = 0;
  @Local btn_hotp_clicked: number = 0;
  @Local TokenHide: boolean = last_token_hide;

  private token_steps: number = 0;

  aboutToAppear(): void {
    getContext(this).eventHub.on('onTimestampChanged', (timestamp: number, force: boolean) => this.onTimestampChanged(timestamp, force));
    this.updateToken();
  }

  onTimestampChanged(timestamp: number, force: boolean): void {
    if (this.Config.TokenType !== otpType.HOTP) {
      this.token_steps = Math.floor(timestamp / this.Config.TokenPeriod);
      this.TokenLeftPeriod = this.Config.TokenPeriod - timestamp % this.Config.TokenPeriod;
      if (this.TokenLeftPeriod == this.Config.TokenPeriod || force) {
        this.updateTOTPToken();
      }
    }
  }

  updateToken() {
    if (this.Config === undefined) {
      return;
    }
    if (this.Config.TokenType == otpType.HOTP) {
      this.updateHOTPToken();
    } else {
      const timestamp = Math.floor(systemDateTime.getTime() / 1000);
      this.onTimestampChanged(timestamp, true);
    }
  }

  updateHOTPToken() {
    this.TokenCounter = this.Config.TokenCounter.toString();
    this.TokenNumber = generateOTP(this.Config, this.Config.TokenCounter).toString().padStart(this.Config.TokenDigits, '0');
  }

  updateTOTPToken() {
    let int_code = generateOTP(this.Config, this.token_steps);
    if (this.Config.TokenType === otpType.Steam) {
      this.TokenNumber = SteamUtils.SteamTokenFromTOTP(int_code);
    } else {
      this.TokenNumber = int_code.toString().padStart(this.Config.TokenDigits, '0');
    }
  }

  build() {
    Row({ space: 10 }) {
      TokenIcon({ icon: this.Config.TokenIcon })
      Column() {
        Text(this.Config.TokenIssuer)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(1)
          .fontSize(20)
          .fontColor($r('app.color.str_main'))
        Text(this.Config.TokenName)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(1)
          .fontSize(10)
          .fontColor($r('app.color.str_gray'))
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      Blank()
      if (this.TokenHide && this.TokenHideEnable) {
        Stack() {
          Text() {
            Span("●●●●")
          }
          .fontColor(Color.Gray)
          .fontSize(30)
        }
        .onClick(() => {
          this.TokenHide = !this.TokenHide;
        })

      } else {
        Column() {
          Text(this.TokenNumber)
            .textAlign(TextAlign.End)
            .textOverflow({ overflow: TextOverflow.MARQUEE })
            .maxLines(1)
            .fontColor($r('app.color.token_number'))
            .fontSize(30)
            .gesture(
              LongPressGesture()
                .onAction(() => {
                  copyText(this.TokenNumber);
                })
            )
          if (this.Config.TokenType == otpType.HOTP) {
            Text(this.TokenCounter)
              .textAlign(TextAlign.End)
              .textOverflow({ overflow: TextOverflow.MARQUEE })
              .maxLines(1)
              .fontColor($r('app.color.str_gray'))
              .fontSize(10)
          }
        }
        .onClick(() => {
          this.TokenHide = this.TokenHideEnable ? !this.TokenHide : this.TokenHide;
        })

        if (this.Config.TokenType == otpType.HOTP) {
          SymbolGlyph($r('sys.symbol.lock_filled_arrow_counterclockwise'))
            .fontColor([$r('app.color.token_number')])
            .fontSize(40)
            .fontWeight(FontWeight.Medium)
            .symbolEffect(new BounceSymbolEffect(EffectScope.WHOLE, EffectDirection.UP),
              this.btn_hotp_clicked)
            .onClick(() => {
              this.btn_hotp_clicked++;
              this.Config.TokenCounter++;
              this.Update(this.Config)
              this.updateHOTPToken();
              last_token_hide = false;
            })
        } else {
          Stack() {
            Text(this.TokenLeftPeriod.toString())
            Progress({ value: this.TokenLeftPeriod, total: this.Config.TokenPeriod, type: ProgressType.Ring })
              .style({ strokeWidth: 8 })
              .width(40)
              .height(40)
          }
        }
      }
    }
    .borderRadius(10)
    .shadow({ radius: 10, color: $r('app.color.shadow'), offsetX: 10, offsetY: 10 })
    .padding(10)
    .justifyContent(FlexAlign.SpaceBetween)
    .width('100%')
    .height(60)
    .backgroundColor($r("app.color.item_bg"))
  }
}

function copyText(text: string) {
  const pasteboardData = pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, text);
  const systemPasteboard = pasteboard.getSystemPasteboard();
  systemPasteboard.setData(pasteboardData); // 将数据放入剪切板
  promptAction.showToast({ message: 'Token copied: ' + text });
}
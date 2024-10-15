import { generateTOTP, generateHOTP } from 'libtotp_mcu.so'
import { systemDateTime } from '@kit.BasicServicesKit';
import { TokenConfig } from '../utils/CustomAppData';

@Preview
@ComponentV2
export struct TokenItem {
  @Require @Param Config: TokenConfig = new TokenConfig();
  @Event Update: (conf: TokenConfig) => void = () => {};

  @Local TokenNumber: string = '000000';
  @Local TokenCounter: string = '0';
  @Local TokenLeftPeriod: number = 0;
  @Local btn_hotp_clicked: number = 0;

  private steam_chars: string = "23456789BCDFGHJKMNPQRTVWXY";
  private steam_digits: number = 5;

  aboutToAppear(): void {
    if (this.Config.TokenType == 2) {
      this.updateHOTPToken();
    } else {
      let timestamp = Math.floor(systemDateTime.getTime() / 1000)
      this.refreshTOTPToken(timestamp);
    }
  }

  updateHOTPToken() {
    this.TokenCounter = this.Config.TokenCounter.toString();
    this.TokenNumber = generateHOTP(
      this.Config.TokenKey.toUpperCase(),
      this.Config.TokenKey.length,
      this.Config.TokenDigits,
      this.Config.TokenCounter,
      0
    ).toString().padStart(this.Config.TokenDigits, '0');
  }

  updateTOTPToken() {
    let timestamp = Math.floor(systemDateTime.getTime() / 1000);
    this.TokenLeftPeriod = this.Config.TokenPeriod - timestamp % this.Config.TokenPeriod;
    if (this.TokenLeftPeriod == this.Config.TokenPeriod) {
      this.refreshTOTPToken(timestamp);
    }
  }

  refreshTOTPToken(timestamp: number) {
    if (this.Config.TokenType === 3) { // steam
      let int_code = generateTOTP(
        this.Config.TokenKey.toUpperCase(),
        this.Config.TokenKey.length,
        this.Config.TokenDigits,
        this.Config.TokenPeriod,
        timestamp
      );
      let total_chars = this.steam_chars.length;
      this.TokenNumber = '';
      for (let index = 0; index < this.steam_digits; index++) {
        let pos = int_code % total_chars;
        this.TokenNumber += this.steam_chars[pos];
        int_code = Math.floor(int_code / total_chars);
      }
    } else {
      this.TokenNumber = generateTOTP(
        this.Config.TokenKey.toUpperCase(),
        this.Config.TokenKey.length,
        this.Config.TokenDigits,
        this.Config.TokenPeriod,
        timestamp
      ).toString().padStart(this.Config.TokenDigits, '0');
    }
  }

  build() {
    Row({ space: 10 }) {
      SymbolGlyph($r('sys.symbol.person_crop_circle_fill'))
        .fontColor([Color.Gray])
        .fontSize(40)
      Column() {
        Text(this.Config.TokenHost)
          .textOverflow({overflow: TextOverflow.Ellipsis})
          .maxLines(1)
          .fontSize(20)
          .fontColor($r('app.color.str_main'))
        Text(this.Config.TokenUser)
          .textOverflow({overflow: TextOverflow.Ellipsis})
          .maxLines(1)
          .fontSize(10)
          .fontColor($r('app.color.str_gray'))
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)
      Blank()
      Column() {
        Text(this.TokenNumber)
          .textAlign(TextAlign.End)
          .textOverflow({overflow: TextOverflow.MARQUEE})
          .maxLines(1)
          .fontColor($r('app.color.token_number'))
          .fontSize(30)
        if (this.Config.TokenType == 2)  { // hotp
          Text(this.TokenCounter)
            .textAlign(TextAlign.End)
            .textOverflow({overflow: TextOverflow.MARQUEE})
            .maxLines(1)
            .fontColor($r('app.color.str_gray'))
            .fontSize(10)
        }
      }
      if (this.Config.TokenType == 2)  { // hotp
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
    .borderRadius(10)
    .shadow({ radius: 10, color: $r('app.color.shadow'), offsetX: 10, offsetY: 10 })
    .padding(10)
    .justifyContent(FlexAlign.SpaceBetween)
    .width('100%')
    .height(60)
    .backgroundColor($r("app.color.item_bg"))
    .onAppear(() => {
      if (this.Config.TokenType === 2) {
        this.updateTOTPToken();
      } else {
        this.updateTOTPToken();
        setInterval(() => {
          this.updateTOTPToken();
        }, 1000)
      }
    })
  }
}
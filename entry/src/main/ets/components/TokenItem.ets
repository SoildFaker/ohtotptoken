import { generateTOTP } from 'libtotp_mcu.so'
import { systemDateTime } from '@kit.BasicServicesKit';
import { TokenConfig } from '../utils/CustomAppData';
import { base32Decode, base32Encode } from '../utils/TokenUtils';

@Preview
@ComponentV2
export struct TokenItem {
  @Require @Param Config: TokenConfig = new TokenConfig()

  @Local TokenNumber: string = '000000'
  @Local TokenLeftPeriod: number = 0

  aboutToAppear(): void {
    let timestamp = Math.floor(systemDateTime.getTime() / 1000)
    this.refreshToken(timestamp)
  }

  updateToken() {
    let timestamp = Math.floor(systemDateTime.getTime() / 1000)
    this.TokenLeftPeriod = this.Config.TokenPeriod - timestamp % this.Config.TokenPeriod
    if (this.TokenLeftPeriod == this.Config.TokenPeriod) {
      this.refreshToken(timestamp)
    }
  }

  refreshToken(timestamp: number) {
    this.TokenNumber = generateTOTP(
      this.Config.TokenKey.toUpperCase(),
      this.Config.TokenKey.length,
      this.Config.TokenDigits,
      this.Config.TokenPeriod,
      timestamp
    ).toString().padStart(this.Config.TokenDigits, '0')
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
      Text(this.TokenNumber)
        .textAlign(TextAlign.End)
        .textOverflow({overflow: TextOverflow.MARQUEE})
        .maxLines(1)
        .fontColor($r('app.color.token_number'))
        .fontSize(30)
      Stack() {
        Text(this.TokenLeftPeriod.toString())
        Progress({ value: this.TokenLeftPeriod, total: this.Config.TokenPeriod, type: ProgressType.Ring })
          .style({ strokeWidth: 8 })
          .width(40)
          .height(40)
      }
    }
    .borderRadius(10)
    .shadow({ radius: 10, color: $r('app.color.shadow'), offsetX: 10, offsetY: 10 })
    .padding(10)
    .justifyContent(FlexAlign.SpaceBetween)
    .width('100%')
    .height(60)
    .backgroundColor($r('app.color.item_background'))
    .onAppear(() => {
      this.updateToken()
      setInterval(() => {
          this.updateToken()
      }, 1000)
    })
  }
}
import { generateTotp } from 'totp-generator'
import { systemDateTime } from '@kit.BasicServicesKit';
import { TokenConfig } from '../utils/CustomAppData';

declare type HashAlgorithm = 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512' | 'SHA3';

@Preview
@ComponentV2
export struct TokenItem {
  @Require @Param Config: TokenConfig = new TokenConfig()

  @Local TokenNumber: string = '000000'
  @Local TokenLeftPeriod: number = 0

  updateToken() {
    this.TokenLeftPeriod = this.Config.TokenPeriod - Math.floor(systemDateTime.getTime() / 1000) % this.Config.TokenPeriod
    this.TokenNumber = generateTotp(this.Config.TokenKey, {
      digits: this.Config.TokenDigits,
      algorithm: this.Config.TokenAlgorithm as HashAlgorithm,
      period: this.Config.TokenPeriod,
    });
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
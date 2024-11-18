import { ConfigurationConstant } from "@kit.AbilityKit";
import { edgeWidths } from "@ohos.arkui.node";

@Preview
@ComponentV2
export struct TokenIcon {
  @Require @Param icon: string = '';

  build() {
    if (this.icon == undefined || this.icon == '') {
      SymbolGlyph($r('sys.symbol.person_crop_circle_fill'))
        .fontColor([Color.Gray])
        .fontSize(40)
    } else {
      if (AppStorage.get<number>('currentColorMode') === ConfigurationConstant.ColorMode.COLOR_MODE_DARK) {
        Image($rawfile(this.icon))
          .width(40)
          .height(40)
          .fillColor($r('app.color.item_fg'))
          .objectFit(ImageFit.Contain)
      } else {
        Image($rawfile(this.icon))
          .width(40)
          .height(40)
          .objectFit(ImageFit.Contain)
      }

    }
  }
}

@Preview
@ComponentV2
export struct SubItemButton {
  @Param symbol: Resource | undefined = $r('sys.symbol.tip_fit_test');
  @Require @Param text: ResourceStr | string = 'TEST';

  build() {
    Button({ type: ButtonType.Normal }) {
      Row() {
        Blank()
          .width(10)
        SymbolGlyph(this.symbol)
          .fontSize(20)
          .fontColor([$r('app.color.str_main')])
        Blank()
          .width(10)
        Text(this.text)
          .width('100%')
          .fontSize(15)
      }
      .alignItems(VerticalAlign.Center)
      .justifyContent(FlexAlign.Start)
    }
    .borderRadius(10)
    .height(40)
    .width('100%')
    .backgroundColor($r('app.color.item_bg'))
    .clickEffect({level:ClickEffectLevel.LIGHT, scale: 0.95})
  }
}
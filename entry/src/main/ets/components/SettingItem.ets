
@Builder
function DefaultBuilder() {
  Text('Empty');
}

@Preview
@ComponentV2
export struct SettingItem {
  @BuilderParam subItemBuilder?: CustomBuilder = DefaultBuilder;
  @Require @Param title: ResourceStr | string = '';

  build() {
    Row() {
      Column({ space: 5 }) {
        Text(this.title)
          .fontSize(20)
        Divider().vertical(false)
        if (this.subItemBuilder) {
          this.subItemBuilder();
        }
      }
      .alignItems(HorizontalAlign.Start)
    }
    .width('100%')
    .backgroundColor($r('app.color.item_bg'))
    .borderRadius(10)
    .shadow({ radius: 10, color: $r('app.color.shadow'), offsetX: 10, offsetY: 10 })
    .padding(10)
  }
}
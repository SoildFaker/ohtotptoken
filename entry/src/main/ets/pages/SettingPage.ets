@Preview
@ComponentV2
export struct SettingPage {
  build() {
    List({ space: 10 }) {
      ListItem(){

      }
      .height(0)

      ListItem() {
        Row() {
          Column() {
            Text($r('app.string.setting_about'))
              .fontSize(20)
            Divider().vertical(false)
            Text("Github:SoildFaker/ohtotptoken")
              .fontSize(10)
              .fontColor($r('app.color.str_gray'))
          }
          .alignItems(HorizontalAlign.Start)
        }
        .backgroundColor($r('app.color.item_bg'))
        .borderRadius(10)
        .shadow({ radius: 10, color: $r('app.color.shadow'), offsetX: 10, offsetY: 10 })
        .padding(10)
      }
      .padding({ left: 10, right: 10})

      ListItem() {
        Row() {
          Column() {
            Text($r('app.string.setting_opensource_leg'))
              .fontSize(20)
            Divider().vertical(false)
            Text("Github:paolostivanin/libcotp\nGithub:Netthaw/TOTP-MCU\nGithub:ss23/fortitoken-mobile-registration")
              .fontSize(10)
              .fontColor($r('app.color.str_gray'))
          }
          .alignItems(HorizontalAlign.Start)
        }
        .backgroundColor($r('app.color.item_bg'))
        .borderRadius(10)
        .shadow({ radius: 10, color: $r('app.color.shadow'), offsetX: 10, offsetY: 10 })
        .padding(10)
      }
      .padding({ left: 10, right: 10})

      ListItem(){

      }
      .height(0)
    }
    .backgroundColor($r('app.color.window_background'))
  }
}
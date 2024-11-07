
@Preview
@CustomDialog
@Component
export struct EncryptionPassWordDialog {
  private textValue: string = '';
  private inputValue: string = '';
  controller?: CustomDialogController;
  cancel: () => void = () => {
  };
  confirm: (text: string) => void = (text: string) => {
  };

  build() {
    Column({ space: 10 }) {
      Text($r('app.string.dialog_backup_password')).fontSize(20).margin({ top: 10, bottom: 10 })
      TextInput({ placeholder: $r('app.string.dialog_backup_password_placeholder'), text: this.textValue })
        .height(60)
        .width('90%')
        .maxLength(16)
        .type(InputType.Password)
        .maxLength(32)
        .showPasswordIcon(true)
        .onChange((value: string) => {
          this.textValue = value
        })
      Flex({ justifyContent: FlexAlign.SpaceAround }) {
        Button($r('app.string.setting_backup_cancel'))
          .onClick(() => {
            if (this.controller != undefined) {
              this.cancel()
              this.controller.close()
            }
          })
          .fontColor($r('app.color.item_fg'))
          .backgroundColor(Color.Transparent)
          .width('100%')
        Button($r('app.string.setting_backup_confirm'))
          .onClick(() => {
            if (this.controller != undefined) {
              this.inputValue = this.textValue
              this.confirm(this.inputValue)
              this.controller.close()
            }
          })
          .fontColor($r('app.color.item_fg'))
          .backgroundColor(Color.Transparent)
          .width('100%')
      }.margin({ bottom: 10 })
    }
    .borderRadius(10)
  }
}
import { TokenConfig } from '../utils/CustomAppData';
import { picker } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { common } from '@kit.AbilityKit';
import { base32Decode, base32Encode, stringToIntArray, intArrayToString, generateFileNameWithDate } from '../utils/TokenUtils'
import promptAction from '@ohos.promptAction'
import Logger from '../utils/Logger';
import MediaFileUri from '../utils/MediaFileUri';
import { MMKV } from '@tencent/mmkv';
import { SubItemToggle } from '../components/SubItemToggle'
import { ItemDescription } from '../components/ItemDescription'

class backup_file {
  magic!: number;
  configs!: Array<TokenConfig>;
}
@CustomDialog
@Component
struct EncryptionPassWordDialog {
  private textValue: string  = '';
  private inputValue: string  = '';
  controller?: CustomDialogController
  cancel: () => void = () => {
  }
  confirm: (text:string) => void = (text:string) => {
  }

  build() {
    Column() {
      Text('Password').fontSize(20).margin({ top: 10, bottom: 10 })
      TextInput({ placeholder: 'input your password...', text: this.textValue }).height(60).width('90%')
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
              this.controller.close()
              this.cancel()
            }
          }).backgroundColor(0xffffff).fontColor(Color.Black)
        Button($r('app.string.setting_backup_confirm'))
          .onClick(() => {
            if (this.controller != undefined) {
              this.inputValue = this.textValue
              this.controller.close()
              this.confirm(this.inputValue)
            }
          }).backgroundColor(0xffffff).fontColor(Color.Red)
      }.margin({ top:10, bottom: 10 })


    }.borderRadius(10)
  }
}

@Preview
@ComponentV2
export struct SettingPage {
  //安全性——隐私模式设置
  @Param app_safety_privacy_enable:boolean =false;
  //安全性应用锁定设置
  @Param app_safety_lock_enable:boolean =false;
  @Require @Param arrConf: Array<TokenConfig> = [];
  @Event backupReload: (conf: Array<TokenConfig>) => void = () => {};
  @Event safetyPrivacyUpdateEvent: (conf: boolean) => void = () => {};
  @Event safetyLockUpdateEvent: (conf: boolean) => void = () => {};

  //备份时是否为导出模式
  private backup_is_input:boolean = true;
  private backup_magic:number = 0x55aaeebb;
  private backup_save_uri: string = '';
  private backup_select_uri: string = '';
  private mediaFileUri: MediaFileUri = new MediaFileUri();

  private dialogController: CustomDialogController | null = new CustomDialogController({
    builder: EncryptionPassWordDialog({
      cancel: ()=> {  },
      confirm: (password:string)=> {
        if (this.backup_is_input) {//如果是导出 就要调用导出加密函数
          this.writeContentForSaveAsFileEncryption(this.backup_save_uri,password);
        }
        else
        {
          //加密导入
          this.readContentFromSelectedFileEncryption(this.backup_save_uri,password);
        }
      },
      textValue: "",
      inputValue: ""
    }),
    cancel: () => {},
    autoCancel: true,
    onWillDismiss:(dismissDialogAction: DismissDialogAction)=> {
      console.info("reason=" + JSON.stringify(dismissDialogAction.reason))
      console.log("dialog onWillDismiss")
      if (dismissDialogAction.reason == DismissReason.PRESS_BACK) {
        dismissDialogAction.dismiss()
      }
      if (dismissDialogAction.reason == DismissReason.TOUCH_OUTSIDE) {
        dismissDialogAction.dismiss()
      }
    },
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0, dy: -20 },
    gridCount: 4,
    customStyle: false,
    cornerRadius: 10,
  })


  async writeContentForSaveAsFile(myUri: string): Promise<void> {
    let backup:backup_file = {magic: this.backup_magic, configs: this.arrConf};
    let backup_string = base32Encode(stringToIntArray(JSON.stringify(backup)));
    this.mediaFileUri.writeFileContent(myUri, backup_string);
    promptAction.showToast({message: `BackUp Success.`})
  }
  //todo 实现加密导出
  async writeContentForSaveAsFileEncryption(myUri: string,password:string): Promise<void> {
    let backup:backup_file = {magic: this.backup_magic, configs: this.arrConf};
    let backup_string = base32Encode(stringToIntArray(JSON.stringify(backup)));
    this.mediaFileUri.writeFileContent(myUri, backup_string);
    promptAction.showToast({message: `BackUp Success.`})
  }

  async readContentFromSelectedFile(myUri: string): Promise<void> {
    let backup_string = this.mediaFileUri.readFileContent(myUri);
    try {
      let backup:backup_file = JSON.parse(intArrayToString(base32Decode(backup_string).buffer as ArrayBuffer));
      if (backup.magic == this.backup_magic) {
        this.backupReload(backup.configs);
      } else {
        promptAction.showToast({message: 'Error: invalid backup file!'})
      }
    } catch (err) {
      promptAction.showToast({message: err.message})
    }

  }
  //todo 实现加密导入
  async readContentFromSelectedFileEncryption(myUri: string,password:string): Promise<void> {
    let backup_string = this.mediaFileUri.readFileContent(myUri);
    try {
      let backup:backup_file = JSON.parse(intArrayToString(base32Decode(backup_string).buffer as ArrayBuffer));
      if (backup.magic == this.backup_magic) {
        this.backupReload(backup.configs);
      } else {
        promptAction.showToast({message: 'Error: invalid backup file!'})
      }
    } catch (err) {
      promptAction.showToast({message: err.message})
    }

  }

  async callFilePickerSaveFile(): Promise<void> {

    this.getUIContext().showAlertDialog(
      {
        title: $r('app.string.setting_backup_output'),
        subtitle: $r('app.string.setting_backup_output_des'),
        message:$r('app.string.setting_backup_output_msg'),
        autoCancel: true,
        alignment: DialogAlignment.Bottom,
        gridCount: 4,
        offset: { dx: 0, dy: -20 },
        buttonDirection: DialogButtonDirection.HORIZONTAL,
        buttons: [
          {
            value: $r('app.string.setting_backup_type_default'),
            action: () => {
              const documentSaveOptions = new picker.DocumentSaveOptions();
              documentSaveOptions.newFileNames = [`totp_backup_${generateFileNameWithDate()}.json`];
              documentSaveOptions.fileSuffixChoices = ['JSON|.json', '.json'];
              let context = getContext(this) as common.Context;
              const documentViewPicker = new picker.DocumentViewPicker(context);
              documentViewPicker.save(documentSaveOptions).then((documentSaveResult: Array<string>) => {
                if (documentSaveResult !== null && documentSaveResult !== undefined && documentSaveResult.length == 1) {
                  this.backup_save_uri = documentSaveResult[0];
                  Logger.info('documentViewPicker.save to file succeed and uris are:' + documentSaveResult);
                  this.writeContentForSaveAsFile(this.backup_save_uri);
                }
              }).catch((err: BusinessError) => {
                Logger.error(`Invoke documentViewPicker.save failed, code is ${err.code}, message is ${err.message}`);
              })
            }
          },
          {
            value: $r('app.string.setting_backup_type_enc'),
            action: () => {
              const documentSaveOptions = new picker.DocumentSaveOptions();
              documentSaveOptions.newFileNames = [`totp_backup_${generateFileNameWithDate()}_.json`];
              documentSaveOptions.fileSuffixChoices = ['BAK|.bak', '.bak'];
              let context = getContext(this) as common.Context;
              const documentViewPicker = new picker.DocumentViewPicker(context);
              documentViewPicker.save(documentSaveOptions).then((documentSaveResult: Array<string>) => {
                if (documentSaveResult !== null && documentSaveResult !== undefined && documentSaveResult.length == 1) {
                  this.backup_save_uri = documentSaveResult[0];
                  Logger.info('documentViewPicker.save to file succeed and uris are:' + documentSaveResult);
                  this.dialogController?.open();
                  //this.writeContentForSaveAsFileEncryption(this.backup_save_uri);
                }
              }).catch((err: BusinessError) => {
                Logger.error(`Invoke documentViewPicker.save failed, code is ${err.code}, message is ${err.message}`);
              })
            }
          },
          {
            value:$r('app.string.setting_backup_cancel'),
            enabled: true,
            defaultFocus: true,
            style: DialogButtonStyle.HIGHLIGHT,
            action: () => {
              console.info('Callback when button3 is clicked')
            }
          },
        ],
        cancel: () => {
          console.info('Closed callbacks')
        },
        onWillDismiss:(dismissDialogAction: DismissDialogAction)=> {
          console.info("reason=" + JSON.stringify(dismissDialogAction.reason))
          console.log("dialog onWillDismiss")
          if (dismissDialogAction.reason == DismissReason.PRESS_BACK) {
            dismissDialogAction.dismiss()
          }
          if (dismissDialogAction.reason == DismissReason.TOUCH_OUTSIDE) {
            dismissDialogAction.dismiss()
          }
        }
      }
    );

  }

  async callFilePickerSelectFile(): Promise<void> {
    const documentSelectOptions = new picker.DocumentSelectOptions();
    documentSelectOptions.maxSelectNumber = 1;
    documentSelectOptions.fileSuffixFilters = ['JSON|.json,BAK|.bak', '.json,.bak'];
    let context = getContext(this) as common.Context;
    const documentViewPicker = new picker.DocumentViewPicker(context);
    documentViewPicker.select(documentSelectOptions).then((documentSelectResult: Array<string>) => {
      if (documentSelectResult !== null && documentSelectResult !== undefined && documentSelectResult.length == 1) {
        this.backup_select_uri = documentSelectResult[0];
        Logger.info('documentViewPicker.select to file succeed and uris are:' + documentSelectResult);
        if (this.backup_select_uri.endsWith('.bak')) {
          //后缀bak为加密包 唤醒加密导入弹窗
          this.dialogController?.open();
        }
        else
        {
          this.readContentFromSelectedFile(this.backup_select_uri);
        }
      }
    }).catch((err: BusinessError) => {
      Logger.error(`Invoke documentViewPicker.select failed, code is ${err.code}, message is ${err.message}`);
    })
  }

  // 在自定义组件即将析构销毁时将dialogController置空
  aboutToDisappear() {
    this.dialogController = null // 将dialogController置空
  }

  build() {
    List({ space: 10 }) {
      ListItem(){

      }
      .height(0)

      ListItem() {
        Row() {
          Column({ space: 5 }) {
            Text($r('app.string.setting_backup'))
              .fontSize(20)
            Divider().vertical(false)
            Row({ space: 5 }) {
              Button({ type: ButtonType.Capsule }) {
                Row() {
                  Text($r('app.string.setting_backup_export'))
                  Blank()
                    .width(10)
                  SymbolGlyph($r('sys.symbol.save_fill'))
                    .fontColor([$r('app.color.str_main')])
                }
                .justifyContent(FlexAlign.SpaceAround)
              }
              .layoutWeight(1)
              .height(30)
              .backgroundColor($r('app.color.item_bg'))
              .onClick(() => {
                this.backup_is_input=true;
                this.callFilePickerSaveFile()
              })
              Divider().vertical(true)
              Button({ type: ButtonType.Capsule }) {
                Row() {
                  Text($r('app.string.setting_backup_import'))
                  Blank()
                    .width(10)
                  SymbolGlyph($r('sys.symbol.folder_fill'))
                    .fontColor([$r('app.color.str_main')])
                }
                .justifyContent(FlexAlign.SpaceBetween)
              }
              .layoutWeight(1)
              .height(30)
              .backgroundColor($r('app.color.item_bg'))
              .onClick(() => {
                this.backup_is_input=false;
                this.callFilePickerSelectFile()
              })
            }
            .height(30)
            .width('100%')
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
          Column({ space: 5 }) {
            Text($r('app.string.setting_safety'))
              .fontSize(20)
            Divider().vertical(false)
            SubItemToggle({title: $r('app.string.setting_safety_privacy'),isOn:this.app_safety_privacy_enable,
              onChange:(IsOn:boolean)=>{
                this.safetyPrivacyUpdateEvent(IsOn);
              }})
            ItemDescription({description: $r('app.string.setting_safety_privacy_des')})
              .margin({
                top: 0,
                bottom: 2,
                left: 12,
                right: 12
              })
            // SubItemToggle({title: $r('app.string.setting_safety_lock'),isOn:this.app_safety_lock_enable,
            //   onChange:(IsOn:boolean)=>{
            //     this.safetyLockUpdateEvent(IsOn);
            // }})
            // ItemDescription({description: $r('app.string.setting_safety_lock_des')})
            //   .margin({
            //     top: 0,
            //     bottom: 2,
            //     left: 12,
            //     right: 12
            //   })
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
          Column({ space: 5 }) {
            Text($r('app.string.setting_about'))
              .fontSize(20)
            Divider().vertical(false)
            Text("Github: SoildFaker/ohtotptoken\nE-mail: enbinli@outlook.com")
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
          Column({ space: 5 }) {
            Text($r('app.string.setting_opensource_leg'))
              .fontSize(20)
            Divider().vertical(false)
            Text("Github: paolostivanin/libcotp\nGithub: Netthaw/TOTP-MCU\nGithub: ss23/fortitoken-mobile-registration")
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
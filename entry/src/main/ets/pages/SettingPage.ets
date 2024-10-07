import { TokenConfig } from '../utils/CustomAppData';
import { picker } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { common } from '@kit.AbilityKit';
import { base32Decode, base32Encode, stringToIntArray, intArrayToString, generateFileNameWithDate } from '../utils/TokenUtils'
import promptAction from '@ohos.promptAction'
import Logger from '../utils/Logger';
import MediaFileUri from '../utils/MediaFileUri';

class backup_file {
  magic!: number;
  configs!: Array<TokenConfig>;
}

@Preview
@ComponentV2
export struct SettingPage {
  @Require @Param arrConf: Array<TokenConfig> = [];
  @Event backupReload: (conf: Array<TokenConfig>) => void = () => {};

  private backup_magic:number = 0x55aaeebb;
  private backup_save_uri: string = '';
  private backup_select_uri: string = '';
  private mediaFileUri: MediaFileUri = new MediaFileUri();

  async writeContentForSaveAsFile(myUri: string): Promise<void> {
    let backup:backup_file = {magic: this.backup_magic, configs: this.arrConf};
    let backup_string = base32Encode(stringToIntArray(JSON.stringify(backup)));
    this.mediaFileUri.writeFileContent(myUri, backup_string);
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

  async callFilePickerSaveFile(): Promise<void> {
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

  async callFilePickerSelectFile(): Promise<void> {
    const documentSelectOptions = new picker.DocumentSelectOptions();
    documentSelectOptions.maxSelectNumber = 1;
    documentSelectOptions.fileSuffixFilters = ['JSON|.json', '.json'];
    documentSelectOptions.defaultFilePathUri = 'file://docs/storage/Users/currentUser/Documents/totp_backup.json'
    let context = getContext(this) as common.Context;
    const documentViewPicker = new picker.DocumentViewPicker(context);
    documentViewPicker.select(documentSelectOptions).then((documentSelectResult: Array<string>) => {
      if (documentSelectResult !== null && documentSelectResult !== undefined && documentSelectResult.length == 1) {
        this.backup_select_uri = documentSelectResult[0];
        Logger.info('documentViewPicker.select to file succeed and uris are:' + documentSelectResult);
        this.readContentFromSelectedFile(this.backup_select_uri);
      }
    }).catch((err: BusinessError) => {
      Logger.error(`Invoke documentViewPicker.select failed, code is ${err.code}, message is ${err.message}`);
    })
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
                  SymbolGlyph($r('sys.symbol.save_fill'))
                    .fontColor([$r('app.color.str_main')])
                }
                .justifyContent(FlexAlign.SpaceAround)
              }
              .layoutWeight(1)
              .height(30)
              .backgroundColor($r('app.color.item_bg'))
              .onClick(() => {
                this.callFilePickerSaveFile()
              })
              Divider().vertical(true)
              Button({ type: ButtonType.Capsule }) {
                Row() {
                  Text($r('app.string.setting_backup_import'))
                  SymbolGlyph($r('sys.symbol.folder_fill'))
                    .fontColor([$r('app.color.str_main')])
                }
                .justifyContent(FlexAlign.SpaceBetween)
              }
              .layoutWeight(1)
              .height(30)
              .backgroundColor($r('app.color.item_bg'))
              .onClick(() => {
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
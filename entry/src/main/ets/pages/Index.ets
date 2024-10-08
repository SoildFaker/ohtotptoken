import { AppStorageV2 } from '@kit.ArkUI';
import { AppRuntimeInfo, TokenConfig } from '../utils/CustomAppData';
import { TOTPConfigDialog } from '../utils/TOTPConfigDialog';
import { FortiConfigDialog } from '../utils/FortiConfigDialog';
import { TokenItem } from '../components/TokenItem';
import { SettingPage } from '../pages/SettingPage'
import { util } from '@kit.ArkTS';
import { fileIo as fs } from '@kit.CoreFileKit';
import { MMKV } from '@tencent/mmkv';
import { BusinessError } from '@kit.BasicServicesKit';
import promptAction from '@ohos.promptAction'

let mmkv = MMKV.defaultMMKV();

@Entry
@ComponentV2
struct Index {
  @Local appInfo: AppRuntimeInfo = AppStorageV2.connect(AppRuntimeInfo, () => new AppRuntimeInfo())!;
  @Local btn_token_add_clicked: number = 0;
  @Local arrConf: Array<TokenConfig> = [];
  private token_keys: string[] = []
  private dialog_totp_config?: CustomDialogController;
  private dialog_forti_config?: CustomDialogController;
  private alert_dialog_str: string =
    getContext(this).resourceManager.getStringSync($r('app.string.alert_remove_confirm_msg'))

  aboutToAppear(): void {
    this.token_keys = mmkv.decodeStringSet('token_keys') ?? []
    let token_str: string = JSON.stringify(new TokenConfig())
    this.token_keys.forEach(key => {
      this.arrConf.push(JSON.parse(mmkv.decodeString(`token_${key}`) ?? token_str))
    })
    let cer_path = getContext(this).cacheDir + "/fmt.ks"
    fs.access(cer_path, fs.AccessModeType.EXIST).then((exist) => {
      if (!exist) {
        fs.open(cer_path, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE).then((cer_file) => {
          let arr= getContext(this).resourceManager.getRawFileContentSync('ftm.ks')
          fs.write(cer_file.fd, arr.buffer).then((cnt) => {
            console.log('store fmt.ks to cache dir')
          })
            .catch((err:BusinessError) => {
              console.error(`${err.message}`)
            })
        })
      }
    })
  }

  addTOTPConfig(conf: TokenConfig): void {
    const idx = this.arrConf.findIndex(_ => _.TokenKey === conf.TokenKey)
    if (idx !== -1) {
      this.arrConf[idx] = conf
      mmkv.encodeString(`token_${conf.TokenKey}`, JSON.stringify(conf))
      promptAction.showToast({message: `token ${conf.TokenKey} updated.`})
    } else {
      this.arrConf.push(conf)
      mmkv.encodeString(`token_${conf.TokenKey}`, JSON.stringify(conf))
      this.token_keys.push(conf.TokenKey)
      mmkv.encodeStringSet('token_keys', this.token_keys)
      promptAction.showToast({message: `token ${conf.TokenKey} added.`})
    }
  }

  updateTOTPConfigs(confs: Array<TokenConfig>): void {
    this.token_keys = confs.map(conf => conf.TokenKey);
    mmkv.encodeStringSet('token_keys', this.token_keys)
    confs.forEach(conf => {
      mmkv.encodeString(`token_${conf.TokenKey}`, JSON.stringify(conf))
    });
    promptAction.showToast({message: `${confs.length} token(s) updated.`})
  }

  @Builder
  TokenAddMenu(){
    Menu() {
      MenuItem({ content: $r('app.string.tab_token_add_key') })
        .onClick(() => {
          this.dialog_totp_config = new CustomDialogController({
            builder: TOTPConfigDialog({
              confirm: (new_conf) => {this.addTOTPConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_totp_config.open()
        })
      MenuItem({ content: $r('app.string.tab_token_add_forti_key') })
        .onClick(() => {
          this.dialog_forti_config = new CustomDialogController({
            builder: FortiConfigDialog({
              confirm: (new_conf) => {this.addTOTPConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_forti_config.open()
        })
    }
  }

  @Builder TokenItemEnd(conf: TokenConfig) {
    Row({ space: 10 }) {
      Button({ type: ButtonType.Circle }) {
        Text() {
          SymbolSpan($r('sys.symbol.trash'))
            .fontSize(30)
            .fontWeight(FontWeight.Medium)
            .fontColor([Color.White])
        }
      }
      .backgroundColor(Color.Red)
      .padding(10)
      .onClick(() => {
        AlertDialog.show({
          message: util.format(this.alert_dialog_str, conf.TokenUser),
          autoCancel: true,
          alignment: DialogAlignment.Center,
          primaryButton: {
            defaultFocus: false,
            value: $r('app.string.dialog_btn_cancel'),
            action: () => {
              return
            }
          },
          secondaryButton: {
            value: $r('app.string.dialog_btn_confirm'),
            fontColor: Color.Red,
            action: () => {
              this.arrConf = this.arrConf.filter(_ => _.TokenKey !== conf.TokenKey)
              this.token_keys = this.token_keys.filter(_ => _ !== conf.TokenKey)
              mmkv.encodeStringSet('token_keys', this.token_keys)
            }
          }
        })
      })
      Button({ type: ButtonType.Circle }) {
        Text() {
          SymbolSpan($r('sys.symbol.square_and_pencil'))
            .fontSize(30)
            .fontWeight(FontWeight.Medium)
            .fontColor([Color.White])
        }
      }
      .backgroundColor(Color.Gray)
      .padding(10)
      .onClick(() => {
        if (conf.TokenType == 0 || conf.TokenType == undefined) {
          this.dialog_totp_config = new CustomDialogController({
            builder: TOTPConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.addTOTPConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_totp_config.open()
        } else {
          this.dialog_forti_config = new CustomDialogController({
            builder: FortiConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.addTOTPConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_forti_config.open()
        }
      })
    }
    .margin({ left:10 })
  }


  build() {
    Column() {
      Row()
        .backgroundColor($r('app.color.tab_bar_bg'))
        .width('100%')
        .height(this.appInfo.appTopAvoidHeight)
      Tabs() {
        TabContent() {
          Stack({ alignContent: Alignment.BottomEnd }) {
            Column() {

              List({ space: 10, initialIndex: 0 }) {
                ListItem() {
                  Row()
                    .height(5)
                    .width('100%')
                }
                ForEach(this.arrConf, (conf: TokenConfig) => {
                  ListItem() {
                    TokenItem({
                      Config: conf
                    })
                  }
                  .padding({ left: 10, right: 10 })
                  .swipeAction({
                    end: {
                      builder: () => { this.TokenItemEnd(this.arrConf.find(_ => _.TokenKey === conf.TokenKey)) },
                    }
                  })
                }, (item: TokenConfig) => {
                  return JSON.stringify(item)
                })
                ListItem() {
                  Row()
                    .width('100%')
                    .height(this.appInfo.appBottomAvoidHeight + 40)
                }
              }
              .layoutWeight(1)
              .width('100%')
              .height('100%')
              .scrollBar(BarState.Off)

            }
            Button({ type: ButtonType.Circle }) {
              SymbolGlyph($r('sys.symbol.plus'))
                .fontSize(40)
                .fontWeight(FontWeight.Bold)
                .fontColor([Color.White])
                .symbolEffect(new BounceSymbolEffect(EffectScope.WHOLE, EffectDirection.UP),
                  this.btn_token_add_clicked)
            }
            .backgroundColor($r('app.color.token_number'))
            .shadow({ radius: 10, color: $r('app.color.shadow') })
            .margin({ bottom: 10, right: 10 })
            .padding(10)
            .bindMenu(this.TokenAddMenu())
            .onClick(() => {
              this.btn_token_add_clicked += 1
            })
          }

        }
        .backgroundColor($r('app.color.window_background'))
        .tabBar($r('app.string.tab_token'))

        TabContent() {
          SettingPage({
            arrConf: this.arrConf,
            backupReload: (conf) => {
              this.arrConf = conf;
              this.updateTOTPConfigs(conf);
            }
          })
            .height('100%')

        }
        .backgroundColor($r('app.color.window_background'))
        .tabBar($r('app.string.tab_setting'))
      }
      .barBackgroundColor($r('app.color.tab_bar_bg'))
      .backgroundColor($r('app.color.window_background'))
      .layoutWeight(1)
    }
  }
}
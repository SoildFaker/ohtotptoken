import { window } from '@kit.ArkUI';
import { TokenConfig, otpType } from '../utils/TokenConfig';
import { TOTPConfigDialog } from '../dialogs/OTPConfigDialog';
import { FortiConfigDialog } from '../dialogs/FortiConfigDialog';
import { TokenItem } from '../components/TokenItem';
import { SettingPage } from '../pages/SettingPage'
import { util } from '@kit.ArkTS';
import { fileIo as fs } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { router } from '@kit.ArkUI';
import promptAction from '@ohos.promptAction'
import { SteamConfigDialog } from '../dialogs/SteamConfigDialog';
import { QRCodeDialog } from '../dialogs/QRCodeDialog';
import { AppPreference } from '../utils/AppPreference';
import { KvManager } from "../utils/KvManager";
import { MMKV } from '@tencent/mmkv';

let mmkv = MMKV.defaultMMKV();
let kvMgr = KvManager.getInstance();

@Entry
@ComponentV2
struct Index {
  @Local btn_token_add_clicked: number = 0;
  @Local arrConf: Array<TokenConfig> = [];
  @Local tabBarIndex: number = 0;
  @Local isLoading: Boolean = true;


  private windowClass = AppStorage.get("windowClass") as window.Window;
  private appBottomAvoidHeight = AppStorage.get("appBottomAvoidHeight") as number;
  private appTopAvoidHeight = AppStorage.get("appTopAvoidHeight") as number;

  private token_uuids: string[] = []
  private dialog_totp_config?: CustomDialogController;
  private dialog_forti_config?: CustomDialogController;
  private dialog_steam_config?: CustomDialogController;
  private dialog_qrcode?: CustomDialogController;
  private alert_dialog_str: string =
    getContext(this).resourceManager.getStringSync($r('app.string.alert_remove_confirm_msg'))

  //build()函数之前执行 如果启用了隐私防截屏 在这里设置为隐私模式
  aboutToAppear(): void {
    router.clear();
    // this.token_uuids = mmkv.decodeStringSet('token_uuids') ?? []
    // let token_str: string = JSON.stringify(new TokenConfig())
    // this.token_uuids.forEach(key => {
    //   this.arrConf.push(JSON.parse(mmkv.decodeString(`token_${key}`) ?? token_str))
    // })
    this.loadTokenConfig();
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

    //设置隐私模式
    if (AppPreference.getSafetyPrivacyEnable()) {
      try {
        this.windowClass.setWindowPrivacyMode(true, (err) => {
          const errCode = err.code;
          if (errCode) {
            console.error('Failed to set the window to privacy mode. Cause:' + JSON.stringify(err));
            return;
          }
          console.info('Succeeded in setting the window to privacy mode.');
        });
      } catch (exception) {
        console.error('Failed to set the window to privacy mode. Cause:' + JSON.stringify(exception));
      }
    }

  }
  //初始化加载token
  async loadTokenConfig(): Promise<void> {
    this.token_uuids = await kvMgr.getValue<string[]>('token_uuids') ?? []
    if (this.token_uuids.length == 0) {//尝试找一下旧版本mmkv有没有数据 如果有就恢复
      let mmkv_token_uuids = mmkv.decodeStringSet('token_uuids') ?? []
      if (mmkv_token_uuids.length != 0) {
        await kvMgr.setValue<string[]>('token_uuids',mmkv_token_uuids)
        this.token_uuids = mmkv_token_uuids;
        let mmkv_token_str: string = JSON.stringify(new TokenConfig())
        mmkv_token_uuids.forEach(key => {
          let tsts=mmkv.decodeString(`token_${key}`);
          if (tsts!=undefined) {
            kvMgr.setString(`token_${key}`, tsts)
          }
          this.arrConf.push(JSON.parse(tsts ?? mmkv_token_str))
        })
      }
    } else {
      let token_str: string = JSON.stringify(new TokenConfig())
      this.token_uuids.forEach(key => {
        kvMgr.getString(`token_${key}`).then((val)=>{
          this.arrConf.push(JSON.parse( val ?? token_str))
        })
      })
    }
    this.isLoading = false;
  }

  async addTokenConfig(conf: TokenConfig): Promise<void> {
    try {
      const idx = this.arrConf.findIndex(_ => _.TokenUUID === conf.TokenUUID)
      if (idx !== -1) {
        this.arrConf[idx] = conf
        //mmkv.encodeString(`token_${conf.TokenUUID}`, JSON.stringify(conf))
        await kvMgr.setString(`token_${conf.TokenUUID}`,JSON.stringify(conf))
        promptAction.showToast({message: `token ${conf.TokenIssuer}:${conf.TokenName} updated.`})
      } else {
        this.arrConf.push(conf)
        //mmkv.encodeString(`token_${conf.TokenUUID}`, JSON.stringify(conf))
        await kvMgr.setString(`token_${conf.TokenUUID}`,JSON.stringify(conf))
        this.token_uuids.push(conf.TokenUUID)
        //mmkv.encodeStringSet('token_uuids', this.token_uuids)
        await kvMgr.setValue<string[]>('token_uuids', this.token_uuids)
        promptAction.showToast({message: `token ${conf.TokenIssuer}:${conf.TokenName} added.`})
      }
    }
    catch(err)
    {
        console.error(`Failed to addTokenConfig.code is ${err.code},message is ${err.message}`);
    };

  }

  updateTokenConfigs(confs: Array<TokenConfig>): void {
    confs.forEach(conf => {
      if (conf.TokenUUID === undefined || conf.TokenUUID === null) {
        conf.TokenUUID = util.generateRandomUUID();
      }
      this.addTokenConfig(conf);
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
              confirm: (new_conf) => {this.addTokenConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_totp_config.open()
        })
      MenuItem({ content: $r('app.string.tab_token_add_forti_key') })
        .onClick(() => {
          this.dialog_forti_config = new CustomDialogController({
            builder: FortiConfigDialog({
              confirm: (new_conf) => {this.addTokenConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_forti_config.open()
        })
      MenuItem({ content: $r('app.string.tab_token_add_stream_key') })
        .onClick(() => {
          this.dialog_steam_config = new CustomDialogController({
            builder: SteamConfigDialog({
              confirm: (new_conf) => {this.addTokenConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_steam_config.open()
        })
    }
  }

  convertToken2URI(conf: TokenConfig): string {
    let prefix = 'otpauth://';
    let otp_type = conf.TokenType == otpType.HOTP ? 'hotp' : 'totp';
    let label = conf.TokenIssuer + ':' + conf.TokenName;
    let period_or_counter = conf.TokenType == otpType.HOTP ? ('&counter=' + conf.TokenCounter) : ('&period=' + conf.TokenPeriod);
    return prefix + otp_type + '/' + label + '?'
      + 'secret=' + conf.TokenSecret + '&issuer=' + conf.TokenIssuer
      + '&digits=' + conf.TokenDigits
      + period_or_counter;
  }

  @Builder
  TokenItemStart(conf: TokenConfig) {
    Row({ space: 10 }) {
      Button({ type: ButtonType.Circle }) {
        Text() {
          SymbolSpan($r('sys.symbol.qrcode'))
            .fontSize(30)
            .fontWeight(FontWeight.Medium)
            .fontColor([Color.White])
        }
      }
      .backgroundColor(Color.Orange)
      .padding(10)
      .onClick(() => {
        this.dialog_qrcode = new CustomDialogController({
          builder: QRCodeDialog({
            content: this.convertToken2URI(conf)
          })
        });
        this.dialog_qrcode.open();
      })
      .margin({ right: 10 })
    }
  }

  @Builder
  TokenItemEnd(conf: TokenConfig) {
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
      .onClick(async () => {
        AlertDialog.show({
          message: util.format(this.alert_dialog_str, conf.TokenName),
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
            action: async () => {
              this.arrConf = this.arrConf.filter(_ => _.TokenUUID !== conf.TokenUUID)
              this.token_uuids = this.token_uuids.filter(_ => _ !== conf.TokenUUID)
              //mmkv.encodeStringSet('token_uuids', this.token_uuids)
              await kvMgr.setValue<string[]>('token_uuids', this.token_uuids)
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
        if (conf.TokenType === otpType.TOTP || conf.TokenType === otpType.HOTP || conf.TokenType === undefined) { // default
          this.dialog_totp_config = new CustomDialogController({
            builder: TOTPConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.addTokenConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_totp_config.open()
        } else if (conf.TokenType === otpType.Forti) { // forti
          this.dialog_forti_config = new CustomDialogController({
            builder: FortiConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.addTokenConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_forti_config.open()
        } else if (conf.TokenType === otpType.Steam) { // steam
          this.dialog_steam_config = new CustomDialogController({
            builder: SteamConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.addTokenConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_steam_config.open()
        }
      })
    }
    .margin({ left: 10 })
  }

  @Builder
  tabBar(text: ResourceStr | string, id: number) {
    Column(){
      Blank()
        .width('100%')
        .height(this.appTopAvoidHeight)
      Text(text)
        .fontWeight(this.tabBarIndex === id ? 500 : 400)
        .fontColor(this.tabBarIndex === id ? $r('app.color.token_number') : $r('app.color.str_main'))
    }
  }

  build() {
    Stack() {
      if (this.isLoading) {
        Column() {
          LoadingProgress()
            .color(Color.White)
            .width(80).height(80)
          Text('Loading..')
            .fontSize(16)
            .fontColor(Color.White)
        }
        .width('100%')
        .height('100%')
        .backgroundColor('#40000000')
        .justifyContent(FlexAlign.Center)
      } else {

        Column() {
          Tabs() {
            TabContent() {
              Stack({ alignContent: Alignment.BottomEnd }) {
                Column() {

                  List({ space: 10, initialIndex: 0 }) {
                    ListItem() {
                      Row()
                        .height(50 + this.appTopAvoidHeight)
                        .width('100%')
                    }
                    ForEach(this.arrConf, (conf: TokenConfig, index: number) => {
                      ListItem() {
                        TokenItem({
                          Config: conf,
                          Update: async  (conf_new) => {
                            this.arrConf[index].TokenCounter = conf_new.TokenCounter;
                            //mmkv.encodeString(`token_${this.arrConf[index].TokenUUID}`, JSON.stringify(this.arrConf[index]))
                            await kvMgr.setString(`token_${this.arrConf[index].TokenUUID}`, JSON.stringify(this.arrConf[index]))
                          }
                        })
                      }
                      .padding({ left: 10, right: 10 })
                      .swipeAction({
                        start: {
                          builder: () => { this.TokenItemStart(this.arrConf.find(_ => _.TokenUUID === conf.TokenUUID)) }
                        },
                        end: {
                          builder: () => { this.TokenItemEnd(this.arrConf.find(_ => _.TokenUUID === conf.TokenUUID)) },
                        }
                      })
                    }, (item: TokenConfig) => {
                      return JSON.stringify(item)
                    })
                    ListItem() {
                      Row()
                        .width('100%')
                        .height(this.appBottomAvoidHeight + 40)
                    }
                  }
                  .layoutWeight(1)
                  .width('100%')
                  .height('100%')
                  .scrollBar(BarState.Off)
                  .edgeEffect(EdgeEffect.Spring, { alwaysEnabled: true })

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
            .tabBar(this.tabBar($r('app.string.tab_token'), 0))
            .tabIndex(0)

            TabContent() {
              SettingPage({
                arrConf: this.arrConf,
                appTopAvoidHeight: this.appTopAvoidHeight,
                appBottomAvoidHeight: this.appBottomAvoidHeight,
                backupReload: (conf) => {
                  this.updateTokenConfigs(conf);
                },
              })
                .height('100%')

            }
            .backgroundColor($r('app.color.window_background'))
            .tabBar(this.tabBar($r('app.string.tab_setting'), 1))
          }
          .barBackgroundColor($r('app.color.tab_bar_bg'))
          .backgroundColor($r('app.color.window_background'))
          .layoutWeight(1)
          .barOverlap(true)
          .barBackgroundColor(Color.Transparent)
          .barBackgroundBlurStyle(BlurStyle.Thin)
          .barHeight(50 + this.appTopAvoidHeight)
          .barMode(BarMode.Fixed)
          .onChange((index) => {
            this.tabBarIndex = index;
          })

        }
      }
    }
    .width('100%')
    .height('100%')
  }
}
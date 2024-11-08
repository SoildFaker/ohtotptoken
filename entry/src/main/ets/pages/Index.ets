import { window } from '@kit.ArkUI';
import { bundleManager,common } from '@kit.AbilityKit';
import { TokenConfig, otpType } from '../utils/TokenConfig';
import { TOTPConfigDialog } from '../dialogs/OTPConfigDialog';
import { FortiConfigDialog } from '../dialogs/FortiConfigDialog';
import { TokenItem } from '../components/TokenItem';
import { SettingPage } from '../pages/SettingPage'
import { HashMap, util } from '@kit.ArkTS';
import { fileIo as fs } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { router } from '@kit.ArkUI';
import promptAction from '@ohos.promptAction'
import { SteamConfigDialog } from '../dialogs/SteamConfigDialog';
import { QRCodeDialog } from '../dialogs/QRCodeDialog';
import { AppPreference } from '../utils/AppPreference';
import { privacyManager } from '@kit.StoreKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import CommonEventManager from '@ohos.commonEventManager';
import { TokenStore } from '../utils/TokenStore';
import { PermissionManager } from '../utils/PermissionManager';
import { DropFilesDialog } from '../dialogs/DropFilesDialog';
import { unifiedDataChannel, uniformTypeDescriptor } from '@kit.ArkData';
import { EncryptionPassWordDialog } from '../dialogs/EncryptionPassWordDialog';
import { faceDetector } from '@kit.CoreVisionKit';
import MediaFileUri from '../utils/MediaFileUri';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import {
  base32Decode,
  base32Encode,
  stringToIntArray,
  intArrayToString,
  generateFileNameWithDate
} from '../utils/TokenUtils'

const TAG = 'PrivacySubscribe';

let tkStore = TokenStore.getInstance();
class backup_file {
  magic!: number;
  version!: number;
  configs!: Array<TokenConfig>;
}
@Entry
@ComponentV2
struct Index {
  @Local btn_token_add_clicked: number = 0;
  @Local all_tokens: TokenConfig[] = [];
  @Local tab_bar_index: number = 0;
  @Local token_loaded: Boolean = true;

  private appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  private windowClass = AppStorage.get("windowClass") as window.Window;
  private appBottomAvoidHeight = AppStorage.get("appBottomAvoidHeight") as number;
  private appTopAvoidHeight = AppStorage.get("appTopAvoidHeight") as number;

  private dialog_totp_config?: CustomDialogController;
  private dialog_forti_config?: CustomDialogController;
  private dialog_steam_config?: CustomDialogController;
  private dialog_qrcode?: CustomDialogController;
  private alert_dialog_str: string =
    getContext(this).resourceManager.getStringSync($r('app.string.alert_remove_confirm_msg'))
  private DropFilesDialogIsOpen:boolean=false;

  private readonly eventId = 'usual.event.PRIVACY_STATE_CHANGED';
  // 订阅者信息, 用于保存创建成功的订阅者对象，后续使用其完成订阅及退订的动作
  private subscriber: CommonEventManager.CommonEventSubscriber | undefined = undefined;
  // 事件列表
  private subscribeInfo: CommonEventManager.CommonEventSubscribeInfo = {
    events: [this.eventId]
  };
  //拖拽文件弹框
  private DropFilesDialogController: CustomDialogController | null = new CustomDialogController({
    builder: DropFilesDialog({
    }),
    cancel: () => {
    },
    autoCancel: true,
    openAnimation:({
      delay: 0,
      duration: 200, // 动画时长
      curve: Curve.EaseInOut, // 动画曲线
    }),
    closeAnimation:({
      delay: 0,
      duration: 200, // 动画时长
      curve: Curve.EaseInOut, // 动画曲线
    }),
    onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
      console.info("reason=" + JSON.stringify(dismissDialogAction.reason))
      console.log("dialog onWillDismiss")
      this.DropFilesDialogIsOpen=false;
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

  private backup_select_uri: string = '';

  //build()函数之前执行 如果启用了隐私防截屏 在这里设置为隐私模式
  aboutToAppear(): void {
    router.clear();
    PermissionManager.getInstance().verifyPermissionsAndPushEvent();
    bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION).then((bundleInfo) => {
      AppStorage.setOrCreate("BundleInfo",bundleInfo);
    });
    AppStorage.setOrCreate("AppPrivacyManageInfoUrl", 'https://www.duan.red/yylx/opt/privacy-statement-zh-cn.htm');

    tkStore.initTokenStore().then(() => {
      getContext(this).eventHub.on('onTokenChanged', () => this.onTokenChanged());
      tkStore.getTokens().then((tokens) => {
        this.all_tokens = tokens;
        this.token_loaded = false;
      });
    });

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

    this.GetPrivacyManageInfo();
    //订阅KV数据库同步完成事件
    getContext(this).eventHub.on('KVStoreSyncComplete',() => {
      //todo 接收同步完成后刷新数据
      tkStore.getTokens().then((tokens) => {
        this.all_tokens = tokens;
        this.token_loaded = false;
        AppPreference.setAppDbKVSyncTime(new Date().toString());
      });

    })
    //订阅RDB数据库同步完成事件
    getContext(this).eventHub.on('RDBStoreSyncComplete',() => {
      //todo 接收同步完成后刷新数据
    })
    //订阅权限变更 主页面不需要取消订阅 没有意义
    this.appCtx.eventHub.on('DATASYNCPermissionsUpdate', (isAccess: boolean) => {
      if (!isAccess) {
        //如果数据同步权限被关闭 则需要将两个同步都关闭
        AppPreference.setRdbSyncEnable(false);
        AppPreference.setRdbCloudSyncEnable(false);
      }
    })

    this.appCtx.eventHub.on('onFileDrop',( plainfile:string)=>{

      this.backup_select_uri = plainfile;
      if (this.backup_select_uri.endsWith('.bak')) {
        //后缀bak为加密包 唤醒加密导入弹窗
        this.dialogController?.open();
      } else if (this.backup_select_uri.endsWith('.json')) {
        this.readContentFromSelectedFile(this.backup_select_uri);
      }
      setTimeout(()=>{
        this.DropFilesDialogIsOpen=false;
        this.DropFilesDialogController?.close();
        },250)
    });
  }

  //region 导入
  private backup_magic: number = 0x55aaeebb;
  private mediaFileUri: MediaFileUri = new MediaFileUri();
  private dialogController: CustomDialogController | null = new CustomDialogController({
    builder: EncryptionPassWordDialog({
      cancel: () => {
      },
      confirm: (password: string) => {
        this.readContentFromSelectedFileEncryption(this.backup_select_uri, password);
      },
      textValue: "",
      inputValue: ""
    }),
    cancel: () => {
    },
    autoCancel: true,
    onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
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
  // 加密导入
  async readContentFromSelectedFileEncryption(myUri: string, password: string): Promise<void> {
    let backup_string = this.mediaFileUri.readFileContent(myUri);
    try {
      this.decryptFile(backup_string, password).then((backup_string) => {
        let backup: backup_file = JSON.parse(backup_string);
        if (backup.magic == this.backup_magic) {
          this.updateTokenConfigs(backup.configs).then(()=>{
            tkStore.sortTokens();
          });
        } else {
          promptAction.showToast({ message: 'Error: invalid backup file!' })
        }
      })
    } catch (err) {
      promptAction.showToast({ message: err.message })
    }

  }
  async decryptFile(file_enc: string, user_key: string): Promise<string> {
    let aes_decoder = cryptoFramework.createCipher('AES128|CBC|PKCS7');
    let aes_iv: cryptoFramework.IvParamsSpec = {
      algName: "IvParamsSpec",
      iv: { data: stringToIntArray('ohtotptokenaesiv') }
    };
    let spec: cryptoFramework.PBKDF2Spec = {
      algName: 'PBKDF2',
      password: user_key,
      salt: new Uint8Array(16),
      iterations: 10000,
      keySize: 16
    };
    let kdf = cryptoFramework.createKdf('PBKDF2|SHA256');
    let symKeyBlob = kdf.generateSecretSync(spec);
    let aesGenerator = cryptoFramework.createSymKeyGenerator('AES128');
    let aes_key = aesGenerator.convertKeySync(symKeyBlob);
    await aes_decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, aes_key, aes_iv).catch((reason: string) => {
      promptAction.showToast({ message: reason });
    });
    return new Promise<string>((resolve) => {
      let file_buf = base32Decode(file_enc);
      aes_decoder.doFinal({ data: file_buf }).then((decryptData) => {
        let decoder = new util.TextDecoder()
        resolve(decoder.decodeToString(decryptData.data));
      }).catch((reason: BusinessError) => {
        promptAction.showToast({ message: reason.message });
      });
    });
  }
  async readContentFromSelectedFile(myUri: string): Promise<void> {
    let backup_string = this.mediaFileUri.readFileContent(myUri);
    try {
      let backup: backup_file = JSON.parse(intArrayToString(base32Decode(backup_string).buffer as ArrayBuffer));
      if (backup.magic == this.backup_magic) {
        this.updateTokenConfigs(backup.configs).then(()=>{
          tkStore.sortTokens();
        });
      } else {
        promptAction.showToast({ message: 'Error: invalid backup file!' })
      }
    } catch (err) {
      promptAction.showToast({ message: err.message })
    }

  }
  //endregion

  async onTokenChanged(): Promise<void> {
    this.all_tokens = await tkStore.getTokens();
  }

  async updateTokenConfig(conf: TokenConfig): Promise<void> {
    await tkStore.updateToken(conf);
    promptAction.showToast({message: `token ${conf.TokenIssuer}:${conf.TokenName} updated.`})
  }

  async updateTokenConfigs(tokens: Array<TokenConfig>): Promise<void> {
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].TokenUUID === undefined) {
        tokens[i].TokenUUID = util.generateRandomUUID();
      }
      if (tokens[i].RankScore === undefined) {
        tokens[i].RankScore = i;
      }
      await this.updateTokenConfig(tokens[i]);
    }
    promptAction.showToast({message: `${tokens.length} token(s) updated.`})
  }

  //准备接入标准化隐私托管
  async GetPrivacyManageInfo(): Promise<void> {
    try {
      let appPrivacyManageInfo: privacyManager.AppPrivacyMgmtInfo = privacyManager.getAppPrivacyMgmtInfo();
      hilog.info(0, 'TAG', "Succeeded in getting AppPrivacyManageInfo type: " + appPrivacyManageInfo["type"]);
      let privacyLinkInfoArray : privacyManager.AppPrivacyLink[] = appPrivacyManageInfo.privacyInfo;
      hilog.info(0, 'TAG', "Succeeded in getting AppPrivacyManageInfo size = " + privacyLinkInfoArray.length);
      for (let i = 0; i < privacyLinkInfoArray.length; i++) {
        hilog.info(0, 'TAG', "Succeeded in getting AppPrivacyManageInfo type = " + privacyLinkInfoArray[i]["type"] + ", version = " + privacyLinkInfoArray[i]["versionCode"] + ", url = " + privacyLinkInfoArray[i]["url"]);

      }
      AppStorage.setOrCreate("AppPrivacyManageInfoUrl", privacyLinkInfoArray[0]["url"]);
    } catch (error) {
      hilog.error(0, 'TAG', "GetAppPrivacyManageInfoPublic exception code: " + error.code + ", exception message: " + error.message);
    }

    hilog.info(0, TAG, "subscribe");
    // 创建订阅者
    CommonEventManager.createSubscriber(this.subscribeInfo).then((commonEventSubscriber) => {
      hilog.info(0, TAG, "createSubscriber");
      this.subscriber = commonEventSubscriber;

      // 订阅公共事件
      try {
        CommonEventManager.subscribe(this.subscriber, (err, data) => {
          if (err) {
            hilog.error(0, TAG, `subscribe failed, code is ${err?.code}, message is ${err?.message}`);
            return;
          }

          let result = JSON.parse(data?.data ?? '{}')?.resultType as number;
          if (result === 1) {
            //向用户申请权限
            //PermissionManager.reqPermissionsFromUser(this.appCtx);
          }
        });
      } catch (error) {
        hilog.error(0, TAG, "init createSubscriber failed, exception code: " + error.code + ", exception message: " + error.message);
      }
    });
  }

  @Builder
  TokenAddMenu() {
    Menu() {
      MenuItem({ content: $r('app.string.tab_token_add_key') })
        .onClick(() => {
          this.dialog_totp_config = new CustomDialogController({
            builder: TOTPConfigDialog({
              confirm: (new_conf) => {this.updateTokenConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_totp_config.open()
        })
        .accessibilityText($r('app.string.tab_token_add_key'))
      MenuItem({ content: $r('app.string.tab_token_add_forti_key') })
        .onClick(() => {
          this.dialog_forti_config = new CustomDialogController({
            builder: FortiConfigDialog({
              confirm: (new_conf) => {this.updateTokenConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_forti_config.open()
        })
        .accessibilityText($r('app.string.tab_token_add_forti_key'))
      MenuItem({ content: $r('app.string.tab_token_add_stream_key') })
        .onClick(() => {
          this.dialog_steam_config = new CustomDialogController({
            builder: SteamConfigDialog({
              confirm: (new_conf) => {this.updateTokenConfig(JSON.parse(new_conf))}
            })
          })
          this.dialog_steam_config.open()
        })
        .accessibilityText($r('app.string.tab_token_add_stream_key'))
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
  TokenItemStart(conf: TokenConfig, index: number) {
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
      Button({ type: ButtonType.Circle }) {
        Text() {
          SymbolSpan($r('sys.symbol.chevron_up'))
            .fontSize(30)
            .fontWeight(FontWeight.Medium)
            .fontColor([Color.White])
        }
      }
      .backgroundColor(Color.Green)
      .padding(10)
      .onClick(() => {
        tkStore.rearrangeToken(index, true).then(() => {
          tkStore.sortTokens();
        });
      })
      Button({ type: ButtonType.Circle }) {
        Text() {
          SymbolSpan($r('sys.symbol.chevron_down'))
            .fontSize(30)
            .fontWeight(FontWeight.Medium)
            .fontColor([Color.White])
        }
      }
      .backgroundColor(Color.Green)
      .padding(10)
      .onClick(() => {
        tkStore.rearrangeToken(index, false).then(() => {
          tkStore.sortTokens();
        });
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
              this.all_tokens = this.all_tokens.filter(_ => _.TokenUUID !== conf.TokenUUID);
              tkStore.deleteToken(conf.TokenUUID);
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
                this.updateTokenConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_totp_config.open()
        } else if (conf.TokenType === otpType.Forti) { // forti
          this.dialog_forti_config = new CustomDialogController({
            builder: FortiConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.updateTokenConfig(JSON.parse(new_conf))
              }
            })
          })
          this.dialog_forti_config.open()
        } else if (conf.TokenType === otpType.Steam) { // steam
          this.dialog_steam_config = new CustomDialogController({
            builder: SteamConfigDialog({
              conf_json: JSON.stringify(conf),
              confirm: (new_conf) => {
                this.updateTokenConfig(JSON.parse(new_conf))
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
        .fontWeight(this.tab_bar_index === id ? 500 : 400)
        .fontColor(this.tab_bar_index === id ? $r('app.color.token_number') : $r('app.color.str_main'))
    }
  }

  build() {
    Stack() {
      if (this.token_loaded) {
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
                    ForEach(this.all_tokens, (token: TokenConfig, index: number) => {
                      ListItem() {
                        TokenItem({
                          Config: token,
                          Update: async (conf_new) => {
                            this.updateTokenConfig(conf_new);
                          }
                        })
                      }
                      .padding({ left: 10, right: 10 })
                      .swipeAction({
                        start: {
                          builder: () => { this.TokenItemStart(token, index) }
                        },
                        end: {
                          builder: () => { this.TokenItemEnd(token) },
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
                  .chainAnimation(true)
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
                .accessibilityText($r('app.string.app_ua_add_token'))
              }

            }
            .backgroundColor($r('app.color.window_background'))
            .tabBar(this.tabBar($r('app.string.tab_token'), 0))
            .tabIndex(0)

            TabContent() {
              SettingPage({
                arrConf: this.all_tokens,
                appTopAvoidHeight: this.appTopAvoidHeight,
                appBottomAvoidHeight: this.appBottomAvoidHeight,
                backupReload: async (conf) => {
                  await this.updateTokenConfigs(conf);
                  tkStore.sortTokens();
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
            this.tab_bar_index = index;
          })

        }
      }
    }
    .width('100%')
    .height('100%')
    .allowDrop([uniformTypeDescriptor.UniformDataType.FILE])
    .onDrop((event?: DragEvent, extraParams?: string) => {
      this.DropFilesDialogIsOpen=false;
      this.DropFilesDialogController?.close();
    })
    .onDragEnter((event) => {
      //promptAction.showToast({message: `onDragEnter`})
      //检测到开始拖拽
      if (!this.DropFilesDialogIsOpen) {
        this.DropFilesDialogIsOpen=true;
        this.DropFilesDialogController?.open();
      }
    })
    .onDragLeave((event) => {
      //promptAction.showToast({message: `onDragLeave`})
      //检测到离开拖拽区域
      this.DropFilesDialogIsOpen=false;
      this.DropFilesDialogController?.close();
    })
    .onDragEnd((event)=>{

    })

  }
}
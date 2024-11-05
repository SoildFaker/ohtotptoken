import { TokenConfig } from '../utils/TokenConfig';
import { picker } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { bundleManager, common } from '@kit.AbilityKit';
import {
  base32Decode,
  base32Encode,
  stringToIntArray,
  intArrayToString,
  generateFileNameWithDate
} from '../utils/TokenUtils'
import promptAction from '@ohos.promptAction'
import Logger from '../utils/Logger';
import MediaFileUri from '../utils/MediaFileUri';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer, util } from '@kit.ArkTS';
import { SubItemToggle } from '../components/SubItemToggle'
import { ItemDescription } from '../components/ItemDescription'
import { router } from '@kit.ArkUI';
import { AppPreference } from '../utils/AppPreference';
import { SubItemButton } from '../components/SubItemButton';
import { SettingItem } from '../components/SettingItem';
import { userAuth } from '@kit.UserAuthenticationKit';
import { PermissionManager } from '../utils/PermissionManager';
import { faceDetector } from '@kit.CoreVisionKit';

class backup_file {
  magic!: number;
  version!: number;
  configs!: Array<TokenConfig>;
}

// region 加密导出输入密码弹框
@Preview
@CustomDialog
@Component
struct EncryptionPassWordDialog {
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

// endregion
@Preview
@ComponentV2
export struct SettingPage {
  @Require @Param arrConf: Array<TokenConfig> = [];
  @Require @Param appBottomAvoidHeight: number = 0;
  @Require @Param appTopAvoidHeight: number = 0;
  @Event backupReload: (conf: Array<TokenConfig>) => void = () => {
  };
  @Local versionName?: string;
  @Local appName?: string;
  @Local RdbSyncEnable: boolean = false;
  @Local RdbCloudSyncEnable: boolean = false;
  @Local Is_loaded: boolean = false;
  //备份时是否为导出模式
  private backup_is_input: boolean = true;
  private backup_magic: number = 0x55aaeebb;
  private backup_save_uri: string = '';
  private backup_select_uri: string = '';
  private mediaFileUri: MediaFileUri = new MediaFileUri();
  private appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  private versionCode?: number;

  aboutToAppear(): void {
    // bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION).then((bundleInfo) => {
    //   this.versionCode = bundleInfo.versionCode;
    //   this.versionName = 'Version:' + bundleInfo.versionName;
    //   this.appName = bundleInfo.name;
    // });
    let bundleInfo = AppStorage.get<bundleManager.BundleInfo>("BundleInfo");
    this.versionCode = bundleInfo?.versionCode;
    this.versionName = 'Version:' + bundleInfo?.versionName;
    this.appName = bundleInfo?.name;
    this.RdbSyncEnable = AppPreference.getRdbSyncEnable();
    this.RdbCloudSyncEnable = AppPreference.getRdbCloudSyncEnable();
    //订阅权限变更
    this.appCtx.eventHub.on('DATASYNCPermissionsUpdate', this.updateDATASYNCPermissions);
  }

  //更新数据同步权限
  updateDATASYNCPermissions(isAccess: boolean) {
    if (!isAccess) {
      //如果数据同步权限被关闭 则需要将两个同步都关闭
      this.RdbSyncEnable = false;
      this.RdbCloudSyncEnable = false;
      AppPreference.setRdbSyncEnable(false);
      AppPreference.setRdbCloudSyncEnable(false);
    }
  }

  //region 加密导入导出
  private dialogController: CustomDialogController | null = new CustomDialogController({
    builder: EncryptionPassWordDialog({
      cancel: () => {
      },
      confirm: (password: string) => {
        if (this.backup_is_input) { // 如果是导出 就要调用导出加密函数
          const documentSaveOptions = new picker.DocumentSaveOptions();
          documentSaveOptions.newFileNames = [`totp_backup_${generateFileNameWithDate()}.bak`];
          documentSaveOptions.fileSuffixChoices = ['BAK|.bak', '.bak'];
          let context = getContext(this) as common.Context;
          const documentViewPicker = new picker.DocumentViewPicker(context);
          documentViewPicker.save(documentSaveOptions).then((documentSaveResult: Array<string>) => {
            if (documentSaveResult !== null && documentSaveResult !== undefined && documentSaveResult.length == 1) {
              this.backup_save_uri = documentSaveResult[0];
              Logger.info('documentViewPicker.save to file succeed and uris are:' + documentSaveResult);
              this.writeContentForSaveAsFileEncryption(this.backup_save_uri, password);
            }
          }).catch((err: BusinessError) => {
            Logger.error(`Invoke documentViewPicker.save failed, code is ${err.code}, message is ${err.message}`);
          })
        } else {
          // 加密导入
          this.readContentFromSelectedFileEncryption(this.backup_select_uri, password);
        }
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

  async writeContentForSaveAsFile(myUri: string): Promise<void> {
    let backup: backup_file = { magic: this.backup_magic, version: this.versionCode ?? 0, configs: this.arrConf };
    let backup_string = base32Encode(stringToIntArray(JSON.stringify(backup)));
    this.mediaFileUri.writeFileContent(myUri, backup_string);
    promptAction.showToast({ message: `BackUp Success.` })
  }

  // 加密导出
  async writeContentForSaveAsFileEncryption(myUri: string, password: string): Promise<void> {
    let backup: backup_file = { magic: this.backup_magic, version: this.versionCode ?? 0, configs: this.arrConf };
    this.encryptFile(JSON.stringify(backup), password).then((backup_string) => {
      this.mediaFileUri.writeFileContent(myUri, backup_string);
      promptAction.showToast({ message: `BackUp Success.` })
    });
  }

  async readContentFromSelectedFile(myUri: string): Promise<void> {
    let backup_string = this.mediaFileUri.readFileContent(myUri);
    try {
      let backup: backup_file = JSON.parse(intArrayToString(base32Decode(backup_string).buffer as ArrayBuffer));
      if (backup.magic == this.backup_magic) {
        this.backupReload(backup.configs);
      } else {
        promptAction.showToast({ message: 'Error: invalid backup file!' })
      }
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

  async encryptFile(file_str: string, user_key: string): Promise<string> {
    let aes_encoder = cryptoFramework.createCipher('AES128|CBC|PKCS7');
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
    aes_encoder.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, aes_key, aes_iv);
    return new Promise<string>((resolve) => {
      aes_encoder.doFinal({ data: new Uint8Array(buffer.from(file_str).buffer) }).then((encryptData) => {
        resolve(base32Encode(encryptData.data));
      }).catch((reason: BusinessError) => {
        promptAction.showToast({ message: reason.message });
      });
    });
  }

  // 加密导入
  async readContentFromSelectedFileEncryption(myUri: string, password: string): Promise<void> {
    let backup_string = this.mediaFileUri.readFileContent(myUri);
    try {
      this.decryptFile(backup_string, password).then((backup_string) => {
        let backup: backup_file = JSON.parse(backup_string);
        if (backup.magic == this.backup_magic) {
          this.backupReload(backup.configs);
        } else {
          promptAction.showToast({ message: 'Error: invalid backup file!' })
        }
      })
    } catch (err) {
      promptAction.showToast({ message: err.message })
    }

  }

  async callFilePickerSaveFile(): Promise<void> {

    this.getUIContext().showAlertDialog(
      {
        title: $r('app.string.setting_backup_output'),
        subtitle: $r('app.string.setting_backup_output_des'),
        message: $r('app.string.setting_backup_output_msg'),
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
              this.dialogController?.open();
            }
          },
          {
            value: $r('app.string.setting_backup_cancel'),
            enabled: true,
            action: () => {
              console.info('Callback when button3 is clicked')
            }
          },
        ],
        cancel: () => {
          console.info('Closed callbacks')
        },
        onWillDismiss: (dismissDialogAction: DismissDialogAction) => {
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
        } else {
          this.readContentFromSelectedFile(this.backup_select_uri);
        }
      }
    }).catch((err: BusinessError) => {
      Logger.error(`Invoke documentViewPicker.select failed, code is ${err.code}, message is ${err.message}`);
    })
  }

  //endregion
  // 在自定义组件即将析构销毁时将dialogController置空
  aboutToDisappear() {
    this.dialogController = null // 将dialogController置空
    this.appCtx.eventHub.off('DATASYNCPermissionsUpdate', this.updateDATASYNCPermissions);
  }

  build() {
    Stack() {
      if (this.Is_loaded) {
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
        List({ space: 10 }) {
          ListItem() {

          }
          .height(50 + this.appTopAvoidHeight)

          ListItem() {
            SettingItem({ title: $r('app.string.setting_backup') }) {
              SubItemButton({
                symbol: $r('sys.symbol.save'),
                text: $r('app.string.setting_backup_export')
              })//.layoutWeight(1)
                .onClick(() => {
                  this.backup_is_input = true;
                  this.callFilePickerSaveFile()
                })
              SubItemButton({
                symbol: $r('sys.symbol.folder'),
                text: $r('app.string.setting_backup_import')
              })//.layoutWeight(1)
                .onClick(() => {
                  this.backup_is_input = false;
                  this.callFilePickerSelectFile()
                })
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            SettingItem({ title: $r('app.string.setting_safety') }) {
              SubItemToggle({
                title: $r('app.string.setting_safety_privacy'), isOn: AppPreference.getSafetyPrivacyEnable(),
                onChange: (IsOn: boolean) => {
                  AppPreference.setSafetyPrivacyEnable(IsOn);
                }
              })
              ItemDescription({ description: $r('app.string.setting_safety_privacy_des') })
              SubItemToggle({
                title: $r('app.string.setting_safety_lock'), isOn: AppPreference.getSafetyLockEnable(),
                onChange: (IsOn: boolean) => {
                  if (IsOn) {
                    try {
                      userAuth.getAvailableStatus(userAuth.UserAuthType.PIN, userAuth.AuthTrustLevel.ATL1);
                    } catch (err) {
                      const error = err as BusinessError;
                      promptAction.showToast({ message: error.message });
                      return;
                    }
                  }
                  AppPreference.setSafetyLockEnable(IsOn);
                }
              })
              ItemDescription({ description: $r('app.string.setting_safety_lock_des') })
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            SettingItem({ title: $r('app.string.data_sync') }) {
              SubItemToggle({
                title: $r('app.string.data_rdb_sync'), isOn: this.RdbSyncEnable,
                onChange: (IsOn: boolean) => {
                  if (IsOn) {
                    PermissionManager.getInstance().reqPermissionsFromUser(this.appCtx);
                  }
                  this.RdbSyncEnable = IsOn;
                  AppPreference.setRdbSyncEnable(IsOn);
                }
              })
              ItemDescription({ description: $r('app.string.data_rdb_sync_des') })
              SubItemToggle({
                title: $r('app.string.data_rdb_cloud_sync'), isOn: this.RdbCloudSyncEnable,
                onChange: (IsOn: boolean) => {
                  if (IsOn) {
                    PermissionManager.getInstance().reqPermissionsFromUser(this.appCtx);
                  }
                  this.RdbCloudSyncEnable = IsOn;
                  AppPreference.setRdbCloudSyncEnable(IsOn);
                }
              })
              ItemDescription({ description: $r('app.string.data_rdb_cloud_sync_des') })
              Divider().vertical(false).height(2).accessibilityLevel("no")
              SubItemButton({
                symbol: $r('sys.symbol.arrow_counterclockwise_clock'),
                text: $r('app.string.data_rdb_sync_details')
              })
                .onClick(() => {
                  router.pushUrl({ url: 'pages/ShowDataSyncDetailsPage' });
                })
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            SettingItem({ title: $r('app.string.setting_agreement_statement') }) {
              SubItemButton({ symbol: $r("sys.symbol.person_shield"), text: $r('app.string.privacy_statement') })
                .onClick(() => {
                  router.pushUrl({ url: 'pages/PrivacyPage' });
                })
              SubItemButton({
                symbol: $r("sys.symbol.doc_plaintext_and_pencil"),
                text: $r('app.string.user_agreement')
              })
                .onClick(() => {
                  router.pushUrl({ url: 'pages/AgreementPage' });
                })
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            SettingItem({ title: $r('app.string.setting_about') }) {
              Hyperlink('https://github.com/SoildFaker/ohtotptoken', 'Github: SoildFaker/ohtotptoken') {
              }
              .height(10)
              Text("E-mail: enbinli@outlook.com\nContributors: @Soildfaker, @eveloki, @lsxuan12138")
                .fontSize(10)
                .fontColor($r('app.color.str_gray'))
              Divider().vertical(false).height(2).accessibilityLevel("no")
              Text(this.appName)
                .fontSize(10)
                .fontColor($r('app.color.str_gray'))
              Text(this.versionName)
                .fontSize(10)
                .fontColor($r('app.color.str_gray'))
              Hyperlink('https://beian.miit.gov.cn', 'APP备案预留') {
              }
              .height(10)
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            SettingItem({ title: $r('app.string.setting_opensource_leg') }) {
              Text("Github: paolostivanin/libcotp\nGithub: Netthaw/TOTP-MCU\nGithub: ss23/fortitoken-mobile-registration\nGithub: andOTP/andOTP - Icons")
                .fontSize(10)
                .fontColor($r('app.color.str_gray'))
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            Row()
              .width('100%')
              .height(this.appBottomAvoidHeight)
          }
        }
        .chainAnimation(true)
        .edgeEffect(EdgeEffect.Spring, { alwaysEnabled: true })
        .scrollBar(BarState.Off)
        .backgroundColor($r('app.color.window_background'))
      }
    }
  }
}
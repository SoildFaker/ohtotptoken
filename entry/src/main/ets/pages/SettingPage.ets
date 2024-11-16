import { TokenConfig } from '../utils/TokenConfig';
import { BusinessError } from '@kit.BasicServicesKit';
import { bundleManager, common } from '@kit.AbilityKit';
import { generateFileNameWithDate } from '../utils/TokenUtils'
import promptAction from '@ohos.promptAction'
import { SubItemToggle } from '../components/SubItemToggle'
import { ItemDescription } from '../components/ItemDescription'
import { router } from '@kit.ArkUI';
import { AppPreference } from '../utils/AppPreference';
import { SubItemButton } from '../components/SubItemButton';
import { SettingItem } from '../components/SettingItem';
import { userAuth } from '@kit.UserAuthenticationKit';
import { PermissionManager } from '../utils/PermissionManager';
import { EncryptionPassWordDialog } from '../dialogs/EncryptionPassWordDialog';
import { restoreFromBackup, saveBackupToFile, TokenBackup } from '../utils/TokenBackup';
import { showSaveFilePicker, showSelectFilePicker } from '../utils/FileUtils';

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
  private backup_select_uri: string = '';
  private appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  private versionCode?: number;
  private str_about_app: string = '';
  private str_opensource_leg: string = '';

  aboutToAppear(): void {
    let bundleInfo = AppStorage.get<bundleManager.BundleInfo>("BundleInfo");
    this.versionCode = bundleInfo?.versionCode;
    this.versionName = 'Version:' + bundleInfo?.versionName;
    this.appName = bundleInfo?.name;
    this.RdbSyncEnable = AppPreference.getRdbSyncEnable();
    this.RdbCloudSyncEnable = AppPreference.getRdbCloudSyncEnable();
    //订阅权限变更
    this.appCtx.eventHub.on('DATASYNCPermissionsUpdate', this.updateDATASYNCPermissions);
    this.str_about_app =
      "Github: SolidFaker/ohtotptoken\n" +
      "E-mail: enbinli@outlook.com\n" +
      "Contributors: @Solidfaker, @eveloki, @lsxuan12138\n" +
      "Bundle Name: " + bundleInfo?.name + "\n" +
      "Version: " + bundleInfo?.versionName;
    this.str_opensource_leg =
      "Github: paolostivanin/libcotp\n" +
      "Github: Netthaw/TOTP-MCU\n" +
      "Github: ss23/fortitoken-mobile-registration\n" +
      "Github: andOTP/andOTP - Icons";
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
  private password_input_dialog: CustomDialogController | null = new CustomDialogController({
    builder: EncryptionPassWordDialog({
      cancel: () => {},
      confirm: (password: string) => {
        if (this.backup_is_input) { // 如果是导出 就要调用导出加密函数
          showSaveFilePicker([`totp_backup_${generateFileNameWithDate()}.bak`], ['BAK|.bak']).then((uris) => {
            const backup: TokenBackup = new TokenBackup(this.versionCode ?? 0, this.arrConf);
            saveBackupToFile(uris[0], backup, true, password).then(() => {
              promptAction.showToast({ message: "Backup Success" });
            }).catch((reason: BusinessError) => {
              promptAction.showToast({ message: reason.message });
            });
          });
        } else { // 加密导入
          restoreFromBackup(this.backup_select_uri, true, password).then((backup) => {
            this.backupReload(backup.configs);
          });
        }
      },
      textValue: "",
      inputValue: ""
    }),
    cancel: () => {},
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
              showSaveFilePicker([`totp_backup_${generateFileNameWithDate()}.json`], ['JSON|.json']).then((uris) => {
                const backup: TokenBackup = new TokenBackup(this.versionCode, this.arrConf);
                saveBackupToFile(uris[0], backup).then(() => {
                  promptAction.showToast({ message: "Backup Success" });
                }).catch((reason: BusinessError) => {
                  promptAction.showToast({ message: reason.message });
                });
              });
            }
          },
          {
            value: $r('app.string.setting_backup_type_enc'),
            action: () => {
              this.password_input_dialog?.open();
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
    showSelectFilePicker(1, ['JSON|.json', 'BAK|.bak']).then((uris) => {
      this.backup_select_uri = uris[0];
      if (this.backup_select_uri.endsWith('.bak')) {
        //后缀bak为加密包 唤醒加密导入弹窗
        this.password_input_dialog?.open();
      } else {
        restoreFromBackup(uris[0]).then((backup) => {
          this.backupReload(backup.configs);
        })
      }
    });
  }

  //endregion
  // 在自定义组件即将析构销毁时将dialogController置空
  aboutToDisappear() {
    this.password_input_dialog = null // 将dialogController置空
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
              }).visibility(Visibility.None)
              ItemDescription({ description: $r('app.string.data_rdb_cloud_sync_des') }).visibility(Visibility.None)
              Divider().vertical(false).height(2)
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
              Text(this.str_about_app)
                .fontSize(10)
                .fontColor($r('app.color.str_gray'))
                .padding({ left: 10 })
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            SettingItem({ title: $r('app.string.setting_opensource_leg') }) {
              Text(this.str_opensource_leg)
                .fontSize(10)
                .fontColor($r('app.color.str_gray'))
                .padding({ left: 10 })
            }
          }
          .padding({ left: 10, right: 10 })

          ListItem() {
            Row(){
              Hyperlink('https://github.com/SolidFaker/ohtotptoken/issues', $r('app.string.app_issue_feedback'))
                .height(10)
                .padding({ left: 10 })
              Hyperlink('https://beian.miit.gov.cn/', '粤ICP备2020075515号-2A')
                .height(10)
                .padding({ left: 10 })
            }
            .justifyContent(FlexAlign.Center)
            .width('100%')
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
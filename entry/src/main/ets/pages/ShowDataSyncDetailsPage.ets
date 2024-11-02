import { router } from '@kit.ArkUI';
import { CommonConstants } from '../utils/CommonConstants';
import { TopNavigationView } from '../components/TopNavigationView';
import { otpType, TokenConfig } from '../utils/TokenConfig';
import { SettingItem } from '../components/SettingItem';
import { deviceInfo } from '@kit.BasicServicesKit';
import { AppPreference } from '../utils/AppPreference';
import { SubItemButton } from '../components/SubItemButton';
import { TokenStore } from '../utils/TokenStore';

@Entry
@ComponentV2
struct ShowDataSyncDetailsPage {
  @Local AppDbKVSyncTime: string = '';
  @Local Is_loaded: boolean = false;

  aboutToAppear(): void {
    this.AppDbKVSyncTime = AppPreference.getAppDbKVSyncTime();
    if (this.AppDbKVSyncTime == '' || this.AppDbKVSyncTime == null) {
      this.AppDbKVSyncTime = '??';
    }
  }

  build() {
    Column() {
      TopNavigationView({
        title: $r('app.string.data_rdb_sync_details'),
        onBackClick: () => {
          router.back();
        }
      })
      RelativeContainer() {
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
                SettingItem({ title: $r('app.string.data_dev_info') }) {
                  Row() {
                    Blank()
                      .width(10)
                    Text(deviceInfo.marketName)
                      .fontSize($r('sys.float.ohos_id_text_size_body2'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary'))
                      .fontWeight(FontWeight.Medium)
                      .textAlign(TextAlign.Start)
                  }

                  Row() {
                    Blank()
                      .width(10)
                    Text(deviceInfo.ODID)
                      .fontSize($r('sys.float.ohos_id_text_size_body2'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary'))
                      .fontWeight(FontWeight.Medium)
                      .textAlign(TextAlign.Start)
                  }
                }

              }
              .padding({ left: 10, right: 10 })

              ListItem() {
                SettingItem({ title: $r('app.string.data_kv_sync_time') }) {
                  Row() {
                    Blank()
                      .width(10)

                    Text(this.AppDbKVSyncTime)
                      .fontSize($r('sys.float.ohos_id_text_size_body2'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary'))
                      .fontWeight(FontWeight.Medium)
                      .textAlign(TextAlign.Start)
                  }

                  Row() {
                    SubItemButton({
                      symbol: $r('sys.symbol.arrow_clockwise'),
                      text: $r('app.string.data_sync_manual')
                    })
                      .onClick(() => {
                        this.Is_loaded=true;
                        TokenStore.getInstance().DataSync().then(()=>{
                          setTimeout(()=>{
                            this.Is_loaded=false;
                            AppPreference.setAppDbKVSyncTime(new Date().toString());
                            this.AppDbKVSyncTime=AppPreference.getAppDbKVSyncTime();
                          },1500)
                        })
                      })
                  }
                }
              }
              .padding({ left: 10, right: 10 })

            }
            .chainAnimation(true)
            .edgeEffect(EdgeEffect.Spring, { alwaysEnabled: true })
            .scrollBar(BarState.Off)
            .backgroundColor($r('app.color.window_background'))
            .width('100%')
          }
        }
      }
    }
    .width('100%')
    .height('100%')
    .padding({ top: AppStorage.get<number>('statusBarHeight'), bottom: 24 })
  }
}
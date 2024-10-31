import { router } from '@kit.ArkUI';
import { CommonConstants } from '../utils/CommonConstants';
import { TopNavigationView } from '../components/TopNavigationView';
import { otpType, TokenConfig } from '../utils/TokenConfig';
import { SettingItem } from '../components/SettingItem';
import { deviceInfo } from '@kit.BasicServicesKit';

@Preview
@Entry
@ComponentV2
struct ShowDataSyncDetailsPage {
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
          List({ space: 10 }) {
            ListItem() {

            }
            ListItem() {
              SettingItem({ title: '设备信息' }) {
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
              SettingItem({ title: '更新时间' }) {
                Row() {
                  Blank()
                    .width(10)
                  Text('???')
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary'))
                    .fontWeight(FontWeight.Medium)
                    .textAlign(TextAlign.Start)
                }
              }

            }
            .padding({ left: 10, right: 10 })

            ListItem() {
              SettingItem({ title: '创建时间' }) {
                Row() {
                  Blank()
                    .width(10)
                  Text('???')
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary'))
                    .fontWeight(FontWeight.Medium)
                    .textAlign(TextAlign.Start)
                }
              }

            }
            .padding({ left: 10, right: 10 })

            ListItem() {
              SettingItem({ title: '手动同步' }) {
                Row() {
                  Blank()
                    .width(10)
                  Text('???')
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary'))
                    .fontWeight(FontWeight.Medium)
                    .textAlign(TextAlign.Start)
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
          .height('100%')
        }
      }

    }
    .width('100%')
    .height('100%')
    .padding({ top: AppStorage.get<number>('statusBarHeight'), bottom: 24 })
  }
}
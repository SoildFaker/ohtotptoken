import { router } from '@kit.ArkUI';
import { CommonConstants } from '../utils/CommonConstants';
import { TopNavigationView } from '../components/TopNavigationView';

@Entry
@ComponentV2
struct ShowCodePage {
  build() {
    Column() {
      TopNavigationView({
        title: '',
        onBackClick: () => {
          router.back();
        }
      })
      RelativeContainer() {
        Text("Hallo World")
          .id('ShowCodePageHelloWorld')
          .fontSize(50)
          .fontWeight(FontWeight.Bold)
          .alignRules({
            center: { anchor: '__container__', align: VerticalAlign.Center },
            middle: { anchor: '__container__', align: HorizontalAlign.Center }
          })
      }

    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
    .padding({ top: AppStorage.get<number>('statusBarHeight'), bottom: 24 })
  }
}
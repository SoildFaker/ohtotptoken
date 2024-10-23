import { router } from '@kit.ArkUI';
import { CommonConstants } from '../utils/CommonConstants';
import { TopNavigationView } from '../components/TopNavigationView';
import { otpType, TokenConfig } from '../utils/TokenConfig';

@Entry
@ComponentV2
struct ShowCodePage {
  @Local TokenNumber: string = '000000';
  @Local TokenCounter: string = '0';
  @Local TokenLeftPeriod: number = 0;
  @Local btn_hotp_clicked: number = 0;
  @Local Config: TokenConfig = new TokenConfig();


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
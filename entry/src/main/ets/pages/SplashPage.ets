import { BusinessError } from '@kit.BasicServicesKit';
import { router } from '@kit.ArkUI';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { userAuth} from '@kit.UserAuthenticationKit';
import { AppPreference } from '../utils/AppPreference';
import { CommonConstants } from '../utils/CommonConstants';
import { common } from '@kit.AbilityKit';

@Entry
@Component
struct SplashPage {
  @State message: string = 'Locked';

  aboutToAppear(): void {
    router.clear();
  }

  requireUserAuth(): void {
    try {
      const rand = cryptoFramework.createRandom();
      const len: number = 16;
      const randData: Uint8Array = rand?.generateRandomSync(len)?.data;
      // 设置认证参数
      const authParam: userAuth.AuthParam = {
        challenge: randData,
        authType: [userAuth.UserAuthType.PIN, userAuth.UserAuthType.FACE, userAuth.UserAuthType.FINGERPRINT],
        authTrustLevel: userAuth.AuthTrustLevel.ATL3,
      };
      // 配置认证界面
      const widgetParam: userAuth.WidgetParam = {
        title: getContext(this).resourceManager.getStringSync($r('app.string.user_auth_prompt').id)
      };
      // 获取认证对象
      const userAuthInstance = userAuth.getUserAuthInstance(authParam, widgetParam);
      console.info('get userAuth instance success');
      // 订阅认证结果
      userAuthInstance.on('result', {
        onResult(result) {
          console.info(`userAuthInstance callback result: ${JSON.stringify(result)}`);
          // 可在认证结束或其他业务需要场景，取消订阅认证结果
          //let rr:userAuth.UserAuthResult =result;
          if (result.result == userAuth.UserAuthResultCode.SUCCESS) {
            //判断验证结果是否正确 只有正确验证了才能跳跃到首页
            router.pushUrl({ url: 'pages/Index' });
          }
          userAuthInstance.off('result');
        }
      });
      console.info('auth on success');
      userAuthInstance.start();
      console.info('auth start success');
    } catch (error) {
      const err: BusinessError = error as BusinessError;
      console.error(`auth catch error. Code is ${err?.code}, message is ${err?.message}`);
    }
  }

  onPageShow(): void {
    if (!AppPreference.getSafetyLockEnable()) {
      router.replaceUrl({ url: 'pages/Index' });
    }
  }

  build() {
    Row() {
      RelativeContainer() {
        Row(){
          Column()
          {
            SymbolGlyph($r('sys.symbol.lock_fill'))
              .fontSize(70)
              .fontWeight(FontWeight.Bold)
              .fontColor([$r('app.color.str_main')])
              .alignRules({
                center: { anchor: '__container__', align: VerticalAlign.Center },
                middle: { anchor: '__container__', align: HorizontalAlign.Center }
              })
              .effectStrategy(2)
            Divider().vertical(false).height(20)
            Text($r('app.string.app_locking'))
              .fontSize(20)
            Text($r('app.string.app_unlock'))
              .fontSize(20)
              .fontColor('#3498db')
              .offset({ top: '40%' })
              .textAlign(TextAlign.Center)
          }
         }.width('80%')
          .height('80%')
          .alignRules({
            top: {anchor: "__container__", align: VerticalAlign.Top},
            bottom : {anchor : "__container__", align : VerticalAlign.Bottom},
            left: {anchor: "__container__", align: HorizontalAlign.Start},
            right : {anchor : "__container__", align: HorizontalAlign.End},
            bias : {vertical : 0.3}
          })
      }
    }
    .height('100%')
    .onClick(() => {
      if (AppPreference.getSafetyLockEnable()) {
        this.requireUserAuth();
      } else {
        router.replaceUrl({ url: 'pages/Index' });
      }
    })

  }
}
import { BusinessError } from '@kit.BasicServicesKit';
import { router } from '@kit.ArkUI';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { userAuth } from '@kit.UserAuthenticationKit';
import { AppPreference } from '../utils/AppPreference';

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
        title: '请进行身份认证',
      };
      // 获取认证对象
      const userAuthInstance = userAuth.getUserAuthInstance(authParam, widgetParam);
      console.info('get userAuth instance success');
      // 订阅认证结果
      userAuthInstance.on('result', {
        onResult(result) {
          console.info(`userAuthInstance callback result: ${JSON.stringify(result)}`);
          // 可在认证结束或其他业务需要场景，取消订阅认证结果
          userAuthInstance.off('result');
          router.pushUrl({ url: 'pages/Index' });
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
    RelativeContainer() {
      SymbolGlyph($r('sys.symbol.lock_fill'))
        .fontSize(50)
        .fontWeight(FontWeight.Bold)
        .fontColor([$r('app.color.str_main')])
        .alignRules({
          center: { anchor: '__container__', align: VerticalAlign.Center },
          middle: { anchor: '__container__', align: HorizontalAlign.Center }
        })
    }
    .height('100%')
    .width('100%')
    .onClick(() => {
      if (AppPreference.getSafetyLockEnable()) {
        this.requireUserAuth();
      } else {
        router.replaceUrl({ url: 'pages/Index' });
      }
    })
  }
}
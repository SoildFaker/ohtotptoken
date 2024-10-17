import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { AppStorageV2, window } from '@kit.ArkUI';
import { BusinessError } from '@kit.BasicServicesKit';
import { AppRuntimeInfo } from '../utils/CustomAppData';
import { MMKV } from '@tencent/mmkv';

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    let appCtx = this.context.getApplicationContext();
    let mmkvRootDir = MMKV.initialize(appCtx);
    console.info('mmkv rootDir: ', mmkvRootDir);
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onCreate');
  }

  onDestroy(): void {
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onWindowStageCreate');

    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(0x0000, 'testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err) ?? '');
        return;
      }

      let windowClass: window.Window = windowStage.getMainWindowSync();
      // 获取应用主窗口后存入AppStorage
      AppStorage.setOrCreate("windowClass",windowClass);
      AppStorage.setOrCreate("windowStage",windowStage);

      let isLayoutFullScreen = true;
      windowClass.setWindowLayoutFullScreen(isLayoutFullScreen)
        .then(() => {
          console.info('Succeeded in setting the window layout to full-screen mode.');
        })
        .catch((err: BusinessError) => {
          console.error('Failed to set the window layout to full-screen mode. Cause:' + JSON.stringify(err));
        });

      let appInfo: AppRuntimeInfo = AppStorageV2.connect(AppRuntimeInfo, () => new AppRuntimeInfo())!

      appInfo.appBottomAvoidHeight = px2vp(windowClass.getWindowAvoidArea(window.AvoidAreaType.TYPE_NAVIGATION_INDICATOR).bottomRect.height);
      appInfo.appTopAvoidHeight = px2vp(windowClass.getWindowAvoidArea(window.AvoidAreaType.TYPE_SYSTEM).topRect.height);
      appInfo.appContext = this.context;
      console.info('top: %d, bottom: %d', appInfo.appTopAvoidHeight, appInfo.appBottomAvoidHeight)

      hilog.info(0x0000, 'testTag', 'Succeeded in loading the content.');
    });
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onBackground');
  }
}

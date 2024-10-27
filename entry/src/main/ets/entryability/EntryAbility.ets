import { AbilityConstant, UIAbility, Want, Configuration,ApplicationStateChangeCallback  } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';
import { BusinessError } from '@kit.BasicServicesKit';
import { WindowUtil } from '../utils/WindowUtil';
import { AppPreference } from '../utils/AppPreference';
import { router } from '@kit.ArkUI';
import { relationalStore  } from '@kit.ArkData';
import { cloudData } from '@kit.ArkData';

//单版本分布式键值数据库
let rdbStore: relationalStore.RdbStore | null = null;

export default class EntryAbility extends UIAbility {

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    AppStorage.setOrCreate("appContext", this.context);
    AppStorage.setOrCreate('currentColorMode', this.context.config.colorMode);
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onCreate');
    WindowUtil.setMissionContinueActive(this.context, false);

    //监听前后台变化
    let applicationStateChangeCallback: ApplicationStateChangeCallback = {
      onApplicationForeground() {
        console.info('applicationStateChangeCallback onApplicationForeground');
      },
      onApplicationBackground() {
        console.info('applicationStateChangeCallback onApplicationBackground');
        //如果启用了锁定检查要回到开屏验证pin
        if (AppPreference.getSafetyLockEnable()) {
          router.pushUrl({ url: 'pages/SplashPage' });
        }
      }
    }

    // 1.获取applicationContext
    let applicationContext = this.context.getApplicationContext();
    try {
      // 2.通过applicationContext注册应用前后台状态监听
      applicationContext.on('applicationStateChange', applicationStateChangeCallback);
    } catch (paramError) {
      console.error(`error: ${(paramError as BusinessError).code}, ${(paramError as BusinessError).message}`);
    }
  }

  onDestroy(): void {
    AppPreference.saveSettings();
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    hilog.info(0x0000, 'testTag', '%{public}s', 'Ability onWindowStageCreate');
    WindowUtil.requestFullScreen(windowStage, this.context);
    AppPreference.loadSettings().then(()=>{
      windowStage.loadContent('pages/SplashPage', (err) => {
        if (err.code) {
          hilog.error(0x0000, 'testTag', 'Failed to load the content. Cause: %{public}s', JSON.stringify(err) ?? '');
          return;
        }

        let windowClass: window.Window = windowStage.getMainWindowSync();
        // 获取应用主窗口后存入AppStorage
        AppStorage.setOrCreate("windowClass", windowClass);
        AppStorage.setOrCreate("windowStage", windowStage);

        let isLayoutFullScreen = true;
        windowClass.setWindowLayoutFullScreen(isLayoutFullScreen)
          .then(() => {
            console.info('Succeeded in setting the window layout to full-screen mode.');
          })
          .catch((err: BusinessError) => {
            console.error('Failed to set the window layout to full-screen mode. Cause:' + JSON.stringify(err));
          });
        // save window avoid area info
        AppStorage.setOrCreate("appBottomAvoidHeight", px2vp(windowClass.getWindowAvoidArea(window.AvoidAreaType.TYPE_NAVIGATION_INDICATOR).bottomRect.height));
        AppStorage.setOrCreate("appTopAvoidHeight", px2vp(windowClass.getWindowAvoidArea(window.AvoidAreaType.TYPE_SYSTEM).topRect.height));

        hilog.info(0x0000, 'testTag', 'Succeeded in loading the content.');
      });
    });
  }
  onWindowStageRestore(windowStage: window.WindowStage): void {
    WindowUtil.requestFullScreen(windowStage, this.context);
  }
  onConfigurationUpdate(newConfig: Configuration): void {
    AppStorage.setOrCreate('currentColorMode', newConfig.colorMode);
    hilog.info(0x0000, 'testTag', 'the newConfig.colorMode is %{public}s', JSON.stringify(AppStorage.get('currentColorMode')) ?? '');
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
  //初始化RDB数据库
  initRdbStore(): void{
    const STORE_CONFIG: relationalStore.StoreConfig = {
      name: "main_rdb_store.db",
      encrypt: true,//加密
      securityLevel: relationalStore.SecurityLevel.S3
    };
    relationalStore.getRdbStore(this.context, STORE_CONFIG, (err: BusinessError, __rdbStore: relationalStore.RdbStore) => {
      rdbStore = __rdbStore;
      if (err) {
        console.error(`Get RdbStore failed, code is ${err.code},message is ${err.message}`);
        return;
      }
      console.info('Get RdbStore successfully.');
    })
    let predicates = new relationalStore.RdbPredicates("EMPLOYEE");
    predicates.inAllDevices();
    rdbStore?.sync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST,predicates, (err, result) => {
      if (err) {
        console.error(`Sync failed, code is ${err.code},message is ${err.message}`);
        return;
      }
      console.info('Sync done.');
      for (let i = 0; i < result.length; i++) {
        console.info(`device= ${result[i][0]}, status= ${result[i][1]}`);
      }
      this.context.eventHub.emit("RDBStoreSyncComplete")
    })
    //端云同步 暂时屏蔽 等待实现
    //todo 实现设置是否开启云同步 默认开启本地设备同步
    //todo 同步完成前台刷新数据
    if (AppPreference.getSRdbCloudSyncEnable())
    {
      //仅WIFI同步
      cloudData.setCloudStrategy(cloudData.StrategyType.NETWORK, [cloudData.NetWorkStrategy.WIFI]).then(() => {
        console.info('Succeeded in setting the cloud strategy');
      }).catch((err: BusinessError) => {
        console.error(`Failed to set cloud strategy. Code: ${err.code}, message: ${err.message}`);
      });
      //同步按照时间策略
      rdbStore?.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, (progressDetails) => {
        console.info(`Progess: ${progressDetails}`);
      }, (err) => {
        if (err) {
          console.error(`Cloud sync failed, code is ${err.code},message is ${err.message}`);
          return;
        }
        console.info('Cloud sync succeeded');
        this.context.eventHub.emit("RDBStoreSyncComplete")
      });
    }

  }

}

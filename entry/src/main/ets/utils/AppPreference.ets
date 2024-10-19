import { PreferenceManager } from "./PreferenceManager";

export class AppPreference {
  private static prefMgr = PreferenceManager.getInstance();

  // 安全性——隐私模式设置
  private static app_safety_privacy_enable: boolean = false;
  // 安全性应用锁定设置
  private static app_safety_lock_enable: boolean = false;

  public static getSafetyPrivacyEnable(): boolean {
    return AppPreference.app_safety_privacy_enable;
  }

  public static getSafetyLockEnable(): boolean {
    return AppPreference.app_safety_lock_enable;
  }

  public static setSafetyPrivacyEnable(enable: boolean): void {
    AppPreference.app_safety_privacy_enable = enable;
    AppPreference.prefMgr.setValue<boolean>('app_safety_privacy_enable', enable);
  }

  public static setSafetyLockEnable(enable: boolean): void {
    AppPreference.app_safety_lock_enable = enable;
    AppPreference.prefMgr.setValue<boolean>('app_safety_lock_enable', enable);
  }

  public static async loadSettings(): Promise<void> {
    await AppPreference.prefMgr.getValue<boolean>('app_safety_privacy_enable').then((val) => {
      AppPreference.setSafetyPrivacyEnable(val ?? false);
    })
    await AppPreference.prefMgr.getValue<boolean>('app_safety_lock_enable').then((val) => {
      AppPreference.setSafetyLockEnable(val ?? false);
    })
  }

  public static saveSettings(): void {
    AppPreference.prefMgr.saveUserData();
  }

  private constructor() {
  }
}
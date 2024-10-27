import { PreferenceManager } from "./PreferenceManager";

export class AppPreference {
  private static prefMgr = PreferenceManager.getInstance();

  // 安全性——隐私模式设置
  private static app_safety_privacy_enable: boolean = false;
  // 安全性应用锁定设置
  private static app_safety_lock_enable: boolean = false;
  // 数据库是否启用云同步
  private static app_db_rds_cloud_sync_enable: boolean = false;
  // 数据库是否启用跨设备流转
  private static app_db_rds_sync_enable: boolean = false;

  //获取是否启用跨设备流转
  public static getRdbSyncEnable(): boolean {
    return AppPreference.app_db_rds_sync_enable;
  }

  public static getRdbCloudSyncEnable(): boolean {
    return AppPreference.app_db_rds_cloud_sync_enable;
  }
  public static getSafetyPrivacyEnable(): boolean {
    return AppPreference.app_safety_privacy_enable;
  }

  public static getSafetyLockEnable(): boolean {
    return AppPreference.app_safety_lock_enable;
  }

  public static setRdbSyncEnable(enable: boolean): void {
    AppPreference.app_db_rds_sync_enable = enable;
    AppPreference.prefMgr.setValue<boolean>('app_db_rds_sync_enable', enable);
  }
  public static setRdbCloudSyncEnable(enable: boolean): void {
    AppPreference.app_db_rds_cloud_sync_enable = enable;
    AppPreference.prefMgr.setValue<boolean>('app_db_rds_cloud_sync_enable', enable);
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
      AppPreference.app_safety_privacy_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_safety_lock_enable').then((val) => {
      AppPreference.app_safety_lock_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_db_rds_cloud_sync_enable').then((val) => {
      AppPreference.app_db_rds_cloud_sync_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_db_rds_sync_enable').then((val) => {
      AppPreference.app_db_rds_sync_enable = val ?? false;
    })
  }

  public static saveSettings(): void {
    AppPreference.prefMgr.saveUserData();
  }

  private constructor() {
  }
}
import { PreferenceManager } from "./PreferenceManager";

export class AppPreference {
  private static prefMgr = PreferenceManager.getInstance();
  // 安全性——隐私模式设置
  private static app_safety_privacy_enable: boolean = false;
  // 安全性应用锁定设置
  private static app_safety_lock_enable: boolean = false;
  // 隐藏令牌
  private static app_safety_hide_token_enable: boolean = false;
  // 数据库是否启用云同步
  private static app_db_rds_cloud_sync_enable: boolean = false;
  // 数据库是否启用跨设备流转
  private static app_db_rds_sync_enable: boolean = false;
  // kv数据库同步时间
  private static app_db_kv_sync_time: string = '';

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

  public static getSafetyHideTokenEnable(): boolean {
    return AppPreference.app_safety_hide_token_enable;
  }

  public static getAppDbKVSyncTime(): string {
    return AppPreference.app_db_kv_sync_time;
  }

  public static setAppDbKVSyncTime(value: string): void {
    AppPreference.app_db_kv_sync_time = value;
    AppPreference.prefMgr.setValue<string>('app_db_kv_sync_time', value);
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

  public static setSafetyHideTokenEnable(enable: boolean): void {
    AppPreference.app_safety_hide_token_enable = enable;
    AppPreference.prefMgr.setValue<boolean>('app_safety_hide_token_enable', enable);
  }

  public static async getKey(key: string): Promise<string | null> {
    try {
      return await AppPreference.prefMgr.getValue<string>(key);
    } catch (ex) {
      return null;
    }

  }

  public static async setKey(key: string, value: string): Promise<void> {
    try {
      return await AppPreference.prefMgr.setValue<string>(key, value);
    } catch (ex) {
    }
  }

  public static async loadSettings(): Promise<void> {
    await AppPreference.prefMgr.getValue<boolean>('app_safety_privacy_enable').then((val) => {
      AppPreference.app_safety_privacy_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_safety_lock_enable').then((val) => {
      AppPreference.app_safety_lock_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_safety_hide_token_enable').then((val) => {
      AppPreference.app_safety_hide_token_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_db_rds_cloud_sync_enable').then((val) => {
      AppPreference.app_db_rds_cloud_sync_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<boolean>('app_db_rds_sync_enable').then((val) => {
      AppPreference.app_db_rds_sync_enable = val ?? false;
    })
    await AppPreference.prefMgr.getValue<string>('app_db_kv_sync_time').then((val) => {
      AppPreference.app_db_kv_sync_time = val ?? '';
    })
  }

  public static saveSettings(): void {
    AppPreference.prefMgr.saveUserData();
  }

  private constructor() {
  }
}
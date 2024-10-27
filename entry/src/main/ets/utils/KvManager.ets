/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { bundleManager, common } from '@kit.AbilityKit';
import { distributedKVStore } from '@kit.ArkData';
import { BusinessError } from '@kit.BasicServicesKit';

export class KvManager {
  //单版本分布式键值数据库
  private _kvMgr: distributedKVStore.KVManager | undefined = undefined;
  private _kvStore: distributedKVStore.SingleKVStore | undefined = undefined;

  private static instance: KvManager;

  private constructor() {

  }

  public static getInstance(): KvManager {
    if (!KvManager.instance) {
      KvManager.instance = new KvManager();
    }
    return KvManager.instance;
  }

  private async initKvStore(ctx: common.UIAbilityContext): Promise<distributedKVStore.SingleKVStore> {
    //初始化键值数据库
    let bundleName = bundleManager.getBundleInfoForSelfSync(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION).name;
    const kvManagerConfig: distributedKVStore.KVManagerConfig = {
      context: ctx,
      bundleName: bundleName,
    }
    this._kvMgr = distributedKVStore.createKVManager(kvManagerConfig);
    const options: distributedKVStore.Options = {
      createIfMissing: true,
      encrypt: true,//加密
      backup: true,//设置数据库文件是否备份
      autoSync: true,//自动同步
      kvStoreType: distributedKVStore.KVStoreType.SINGLE_VERSION,//表示单版本数据库。 数据不分设备，设备之间修改相同的Key会覆盖。
      securityLevel: distributedKVStore.SecurityLevel.S3, //对于token密钥采菊表示数据库的安全级别为高级别，数据的泄露、篡改、破坏、销毁可能会给个人或组织导致严峻的不利影响。
    };
    return this._kvMgr.getKVStore('main_store', options);
  }

  async initKvManager(): Promise<void> {
    let ctx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
    await this.initKvStore(ctx).then((store) => {
      this._kvStore = store;
      //订阅同步完成事件
      this._kvStore.on('syncComplete', (data: [string, number][]) => {
        console.info(`syncComplete ${data}`);
        ctx.eventHub.emit('KVStoreSyncComplete');
      });
    }).catch((reason: BusinessError) => {
      console.error(reason.message);
    });
  }

  async setValue<T>(key: string, value: T): Promise<void> {
    if (this._kvStore) {
      await  this._kvStore.put(key, JSON.stringify(value));
    }
  }

  async getValue<T>(key: string): Promise<T | null> {
    if (this._kvStore) {
      return this._kvStore.get(key).then((data: boolean | string | number | Uint8Array) => {
        let value: T | null = null;
        if (data) {
          value = JSON.parse(data as string) as T;
        }
        return value;
      }).catch(() => {
        return null;
      });
    }
    return null;
  }

  async setString(key: string, value: string): Promise<void> {
    if (this._kvStore) {
     this._kvStore.put(key, value, (err) => {
          if (err != undefined) {
            console.error(`Failed to put.code is ${err.code},message is ${err.message}`);
            return;
          }
          console.info("Succeeded in putting");
     });
    }
  }

  async getString(key: string): Promise<string|null> {
    if (this._kvStore) {
      return this._kvStore.get(key).then((data: boolean | string | number | Uint8Array) => {
        let value: string | null = null;
        if (data) {
          value = data as string;
        }
        return value;
      }).catch(() => {
        return null;
      });
    }
    return null;
  }


  async deleteValue(key: string): Promise<void> {
    if (this._kvStore) {
      this._kvStore.delete(key).then(() => {
        return;
      });
    }
  }

}
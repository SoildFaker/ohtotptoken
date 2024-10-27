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

import { common } from '@kit.AbilityKit';
import { relationalStore } from '@kit.ArkData';
import { AppPreference } from './AppPreference';
import { cloudData } from '@kit.ArkData';
import { BusinessError } from '@kit.BasicServicesKit';

//rdb数据库管理 todo预备后面做云同步方案
export class RdbManager {
  private appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  private _rdbStore: relationalStore.RdbStore | undefined = undefined;
  private static instance: RdbManager;

  private constructor() {
    this.initPreference();
  }

  public static getInstance(): RdbManager {
    if (!RdbManager.instance) {
      RdbManager.instance = new RdbManager();
    }
    return RdbManager.instance;
  }

  async initPreference(): Promise<void> {
    this._rdbStore = AppStorage.get<relationalStore.RdbStore>('rdbStore');
  }

  //同步
  async DataSync(): Promise<void> {
    if (AppPreference.getRdbSyncEnable()) {
      let predicates = new relationalStore.RdbPredicates("EMPLOYEE");
      predicates.inAllDevices();
      this._rdbStore?.sync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, predicates, (err, result) => {
        if (err) {
          console.error(`Sync failed, code is ${err.code},message is ${err.message}`);
          return;
        }
        console.info('Sync done.');
        for (let i = 0; i < result.length; i++) {
          console.info(`device= ${result[i][0]}, status= ${result[i][1]}`);
        }
        this.appCtx.eventHub.emit("RDBStoreSyncComplete")
      })
    }
    //端云同步 暂时屏蔽 等待实现
    //todo 实现设置是否开启云同步 默认开启本地设备同步
    //todo 同步完成前台刷新数据
    if (AppPreference.getRdbCloudSyncEnable()) {
      //仅WIFI同步
      cloudData.setCloudStrategy(cloudData.StrategyType.NETWORK, [cloudData.NetWorkStrategy.WIFI]).then(() => {
        console.info('Succeeded in setting the cloud strategy');
      }).catch((err: BusinessError) => {
        console.error(`Failed to set cloud strategy. Code: ${err.code}, message: ${err.message}`);
      });
      //同步按照时间策略
      this._rdbStore?.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, (progressDetails) => {
        console.info(`Progess: ${progressDetails}`);
      }, (err) => {
        if (err) {
          console.error(`Cloud sync failed, code is ${err.code},message is ${err.message}`);
          return;
        }
        console.info('Cloud sync succeeded');
        //this.context.eventHub.emit("RDBStoreSyncComplete")
      });
    }
  }
}
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
import { distributedKVStore } from '@kit.ArkData';
import { BusinessError } from '@kit.BasicServicesKit';


export class KvManager {
  //单版本分布式键值数据库
  private _kvStore: distributedKVStore.SingleKVStore | undefined = undefined;

  private static instance: KvManager;

  private constructor() {
    this.initPreference();
  }

  public static getInstance(): KvManager {
    if (!KvManager.instance) {
      KvManager.instance = new KvManager();
    }
    return KvManager.instance;
  }

  async initPreference(): Promise<void> {
    this._kvStore = AppStorage.get<distributedKVStore.SingleKVStore>('kvStore');
  }

  async setValue<T>(key: string, value: T): Promise<void> {
    if (this._kvStore) {
      await  this._kvStore.put(key, JSON.stringify(value));
    }
  }

  async getValue<T>(key: string): Promise<T | null> {
    if (this._kvStore) {
      // await this._kvStore.get(key, (err, data: boolean | string | number | Uint8Array) => {
      //   let value: T | null = null;
      //   if (err != undefined) {
      //     console.error(`Failed to get.code is ${err.code},message is ${err.message}`);
      //     return;
      //   }
      //   value = JSON.parse(data as string) as T;
      //   return value;
      // });
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
      // this._kvStore.get(key, (err, data: boolean | string | number | Uint8Array) => {
      //   let value: string|null = null;
      //   if (err != undefined) {
      //     console.error(`Failed to get.code is ${err.code},message is ${err.message}`);
      //     return;
      //   }
      //   value = data as string;
      //   return value;
      // });
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
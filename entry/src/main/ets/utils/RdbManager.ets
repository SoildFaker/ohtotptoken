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
import { relationalStore  } from '@kit.ArkData';

//rdb数据库管理 todo预备后面做云同步方案
export class RdbManager {
  //单版本分布式键值数据库
  private _kvStore: relationalStore.RdbStore | undefined = undefined;

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
    this._kvStore = AppStorage.get<relationalStore.RdbStore>('rdbStore');
  }

}
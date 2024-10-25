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

import { router } from '@kit.ArkUI';
import { webview } from '@kit.ArkWeb';
import { CommonConstants } from '../utils/CommonConstants';
import { TopNavigationView } from '../components/TopNavigationView';

@Entry
@Component
struct PrivacyPage {
  @State webViewController: webview.WebviewController = new webview.WebviewController();
  @State AppPrivacyManageInfoUrl:string ='';
  aboutToAppear(): void {
     this.AppPrivacyManageInfoUrl=AppStorage.get("AppPrivacyManageInfoUrl") as string;
  }

  build() {
    Column() {
      TopNavigationView({
        title: $r('app.string.privacy_statement'),
        onBackClick: () => {
          router.back();
        }
      })
      Stack() {
        Web({ controller: this.webViewController, src: this.AppPrivacyManageInfoUrl})
          .darkMode(WebDarkMode.Auto)
          .domStorageAccess(true)
          .zoomAccess(true)
          .fileAccess(true)
          .mixedMode(MixedMode.All)
          .cacheMode(CacheMode.Default)
          .javaScriptAccess(true)
          .width(CommonConstants.FULL_PERCENT)
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
    .padding({ top: AppStorage.get<number>('statusBarHeight'), bottom: 24 })
  }
}
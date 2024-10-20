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

import { CommonConstants } from '../utils/CommonConstants';

@Builder
function DefaultBuilder() {
}

@Component
export struct TopNavigationView {
  title?: ResourceStr;
  @BuilderParam menuView?: CustomBuilder = DefaultBuilder;
  onBackClick?: Function;

  build() {
    Row() {
      if (this.onBackClick) {
        Image($r('app.media.ic_back'))
          .width($r('app.float.interactive_button_height'))
          .height($r('app.float.interactive_button_height'))
          .margin({ right: $r('app.float.lg_padding_margin') })
          .onClick(() => this.onBackClick?.())
      }

      Text(this.title)
        .fontSize($r('app.float.title_text_size'))
        .fontWeight(FontWeight.Bold)
        .textAlign(TextAlign.Start)
        .layoutWeight(1)

      Row() {
        if (this.menuView) {
          this.menuView()
        }
      }
    }
    .alignItems(VerticalAlign.Center)
    .justifyContent(FlexAlign.SpaceBetween)
    .width(CommonConstants.FULL_PERCENT)
    .height($r('app.float.navigation_height'))
    .padding({
      left: $r('app.float.xxl_padding_margin'),
      right: $r('app.float.xxl_padding_margin')
    })
  }
}



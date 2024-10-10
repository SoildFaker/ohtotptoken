/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

@Component
export struct SubItemToggle {
  @LocalStorageProp('currentBreakpoint') curBp: string = 'sm';
  private title: string | Resource = '';
  private isOn: boolean = false;

  build() {
    Row() {
      Text(this.title)
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
        .textAlign(TextAlign.Start)

      Blank()

      Toggle({ type: ToggleType.Switch, isOn: this.isOn })
        .id('ToggleSwitch')
        .width(36)
        .height(20)
        .selectedColor('#007DFF')
    }
    .height(48)
    .width('100%')
    .padding({left: 8, right: 8})
    .borderRadius(24)
    .backgroundColor($r('app.color.itemInactivated'))
  }
}
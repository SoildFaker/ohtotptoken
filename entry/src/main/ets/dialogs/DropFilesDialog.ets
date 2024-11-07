import { unifiedDataChannel, uniformTypeDescriptor } from '@kit.ArkData';
//文件拖拽
@Preview
@CustomDialog
@Component
export struct DropFilesDialog {
  @State triggerValueReplace: number = 0;
  @State replaceFlag:boolean =false;
  controller?: CustomDialogController;
  build() {
    Column({ space: 10}) {
      Row()
      {
        Row()
        {
          SymbolGlyph(this.replaceFlag ? $r('sys.symbol.chevron_down_2_circle') : $r('sys.symbol.arrow_down_circle'))
            .align(Alignment.Top)
            .fontWeight(FontWeight.Lighter)
            .fontSize(96)
            .symbolEffect(new ReplaceSymbolEffect(EffectScope.WHOLE), this.triggerValueReplace)
        }
        .width('100%')
        .height('40%')
        .allowDrop([uniformTypeDescriptor.UniformDataType.FILE])
        .onDrop((event?: DragEvent, extraParams?: string) => {
          console.log("enter onDrop")

        })
        .onDragEnter((event) => {
          this.replaceFlag=true;
          this.triggerValueReplace = this.triggerValueReplace + 1;
        })
        .onDragLeave((event) => {
          this.replaceFlag=false;
          this.triggerValueReplace = this.triggerValueReplace + 1;
        })
        .backgroundColor(0xdeb887).border({ width: 1 })
      }
      .width('90%')
      .height('90%')

    }
    .borderRadius(10)
  }
}
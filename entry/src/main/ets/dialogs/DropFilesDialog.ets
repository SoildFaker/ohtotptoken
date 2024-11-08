import { unifiedDataChannel, uniformTypeDescriptor } from '@kit.ArkData';
import { bundleManager,common } from '@kit.AbilityKit';
//文件拖拽
@Preview
@CustomDialog
@Component
export struct DropFilesDialog {
  @State triggerValueReplace: number = 0;
  @State replaceFlag:boolean =false;
  controller?: CustomDialogController;
  private appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  build() {
    Column({ space: 10}) {
      Row()
      {
        Row()
        {
          Column()
          {
            SymbolGlyph(this.replaceFlag ? $r('sys.symbol.chevron_down_2_circle') : $r('sys.symbol.arrow_down_circle'))
              .fontWeight(FontWeight.Lighter)
              .fontSize(96)
              .fontColor([Color.Blue, Color.Black, Color.White])
              .symbolEffect(new ReplaceSymbolEffect(EffectScope.WHOLE), this.triggerValueReplace)
            Text($r('app.string.drop_file_import_data'))
              .fontSize(20)
              .fontColor($r('app.color.str_gray'))
          }

        }
        .width('100%')
        .height('40%')
        .justifyContent(FlexAlign.Center)
        .allowDrop([uniformTypeDescriptor.UniformDataType.FILE])
        .onDrop((event?: DragEvent, extraParams?: string) => {
          console.log("enter onDrop")
          if (event!=null) {
            let records: Array<unifiedDataChannel.UnifiedRecord> = event.getData().getRecords();
            let plainfile: unifiedDataChannel.File = records[0] as unifiedDataChannel.File;
            this.appCtx.eventHub.emit('onFileDrop',plainfile.uri);
          }
        })
        .onDragEnter((event) => {
          this.replaceFlag=true;
          this.triggerValueReplace = this.triggerValueReplace + 1;
        })
        .onDragLeave((event) => {
          this.replaceFlag=false;
          this.triggerValueReplace = this.triggerValueReplace + 1;
        })
        .onDragEnd((event: DragEvent) =>{
        })
      }
      .width('90%')
      .height('90%')

    }
    .borderRadius(10)
  }
}
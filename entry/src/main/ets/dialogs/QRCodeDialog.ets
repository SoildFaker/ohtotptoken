import { scanCore, generateBarcode } from '@kit.ScanKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { image } from '@kit.ImageKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

@Preview
@CustomDialog
export struct QRCodeDialog {
  controller?: CustomDialogController;
  @Prop content: string = '';
  @State pixelMap: image.PixelMap | undefined = undefined

  aboutToAppear(): void {
    this.pixelMap = undefined;
    let options: generateBarcode.CreateOptions = {
      scanType: scanCore.ScanType.QR_CODE,
      height: 400,
      width: 400
    }
    try {
      // 码图生成接口，成功返回PixelMap格式图片
      generateBarcode.createBarcode(this.content, options).then((pixelMap: image.PixelMap) => {
        this.pixelMap = pixelMap;
      }).catch((error: BusinessError) => {
        hilog.error(0x0001, '[generateBarcode]',
          `Failed to get PixelMap by promise with options. Code: ${error.code}, message: ${error.message}`);
      })
    } catch (error) {
      hilog.error(0x0001, '[generateBarcode]',
        `Failed to createBarcode by promise with options. Code: ${error.code}, message: ${error.message}`);
    }
  }

  build() {
    Flex({ justifyContent: FlexAlign.Center }) {
      if (this.pixelMap) {
        Image(this.pixelMap).width(300).height(300).objectFit(ImageFit.Contain)
      }
    }
    .padding(20)
  }
}
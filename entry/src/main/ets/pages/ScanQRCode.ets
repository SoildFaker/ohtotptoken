
@Entry
@ComponentV2
struct ScanQRCode {
  pathStack: NavPathStack = new NavPathStack()

  build() {
    NavDestination() {
      RelativeContainer() {

      }
      .height('100%')
      .width('100%')
    }
    .title('QR Code Scan')
    .onReady((context: NavDestinationContext) => {
      this.pathStack = context.pathStack
    })
  }
}
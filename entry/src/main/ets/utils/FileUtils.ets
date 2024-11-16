import { fileIo, picker } from "@kit.CoreFileKit";
import { common } from '@kit.AbilityKit';
import { intArrayToString } from "./TokenUtils";

const BUFFER_SIZE = 4096;

export async function readFileContent(uri: string): Promise<string> {
  let content = '';
  return fileIo.open(uri, fileIo.OpenMode.READ_ONLY).then((f) => {
    let buffer = new ArrayBuffer(BUFFER_SIZE);
    let offset = 0;
    let readOut = 0;
    do {
      readOut = fileIo.readSync(f.fd, buffer, { offset: offset });
      content += intArrayToString(buffer.slice(0, readOut));
      offset += BUFFER_SIZE;
    } while (readOut == BUFFER_SIZE)
    fileIo.close(f.fd);
    return content;
  });
}

export async function writeFileContent(uri: string, content: string): Promise<void> {
  fileIo.open(uri, fileIo.OpenMode.READ_WRITE).then((f) => {
    fileIo.write(f.fd, content).then(() => {
      fileIo.close(f.fd);
    });
  });
}

export async function showSelectFilePicker(max_num: number, filters: string[]): Promise<string[]> {
  const documentSelectOptions = new picker.DocumentSelectOptions();
  documentSelectOptions.maxSelectNumber = max_num;
  documentSelectOptions.fileSuffixFilters = filters;
  let context = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  const documentViewPicker = new picker.DocumentViewPicker(context);
  return documentViewPicker.select(documentSelectOptions);
}

export async function showSaveFilePicker(name: string[], filters: string[]): Promise<string[]> {
  const documentSaveOptions = new picker.DocumentSaveOptions();
  documentSaveOptions.newFileNames = name;
  documentSaveOptions.fileSuffixChoices = filters;
  let context = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
  const documentViewPicker = new picker.DocumentViewPicker(context);
  return documentViewPicker.save(documentSaveOptions);
}
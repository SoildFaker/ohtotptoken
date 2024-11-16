import { BusinessError } from '@kit.BasicServicesKit';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer, util } from '@kit.ArkTS';
import { stringToIntArray } from '../utils/TokenUtils'
import promptAction from '@ohos.promptAction'

export async function decryptFile(file_buf: Uint8Array, user_key: string): Promise<string> {
  let aes_decoder = cryptoFramework.createCipher('AES128|CBC|PKCS7');
  let aes_iv: cryptoFramework.IvParamsSpec = {
    algName: "IvParamsSpec",
    iv: { data: stringToIntArray('ohtotptokenaesiv') }
  };
  let spec: cryptoFramework.PBKDF2Spec = {
    algName: 'PBKDF2',
    password: user_key,
    salt: new Uint8Array(16),
    iterations: 10000,
    keySize: 16
  };
  let kdf = cryptoFramework.createKdf('PBKDF2|SHA256');
  let symKeyBlob = kdf.generateSecretSync(spec);
  let aesGenerator = cryptoFramework.createSymKeyGenerator('AES128');
  let aes_key = aesGenerator.convertKeySync(symKeyBlob);
  await aes_decoder.init(cryptoFramework.CryptoMode.DECRYPT_MODE, aes_key, aes_iv)
    .catch((reason: string) => {
      promptAction.showToast({ message: reason });
    });
  return new Promise<string>((resolve) => {
    aes_decoder.doFinal({ data: file_buf }).then((decryptData) => {
      let decoder = new util.TextDecoder()
      resolve(decoder.decodeToString(decryptData.data));
    }).catch((reason: BusinessError) => {
      promptAction.showToast({ message: reason.message });
    });
  });
}

export async function encryptFile(file_str: string, user_key: string): Promise<Uint8Array> {
  let aes_encoder = cryptoFramework.createCipher('AES128|CBC|PKCS7');
  let aes_iv: cryptoFramework.IvParamsSpec = {
    algName: "IvParamsSpec",
    iv: { data: stringToIntArray('ohtotptokenaesiv') }
  };
  let spec: cryptoFramework.PBKDF2Spec = {
    algName: 'PBKDF2',
    password: user_key,
    salt: new Uint8Array(16),
    iterations: 10000,
    keySize: 16
  };
  let kdf = cryptoFramework.createKdf('PBKDF2|SHA256');
  let symKeyBlob = kdf.generateSecretSync(spec);
  let aesGenerator = cryptoFramework.createSymKeyGenerator('AES128');
  let aes_key = aesGenerator.convertKeySync(symKeyBlob);
  aes_encoder.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, aes_key, aes_iv);
  return aes_encoder.doFinal({ data: new Uint8Array(buffer.from(file_str).buffer) }).then((encryptData) => {
    return encryptData.data;
  });
}

import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { buffer, HashSet } from '@kit.ArkTS';
import { TokenConfig } from './CustomAppData';

const RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RFC4648_HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export type Base32Variant = 'RFC3548' | 'RFC4648' | 'RFC4648-HEX' | 'Crockford';

export type HMACAlgorithm = 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512' | 'SM3' | 'MD5';

function readChar(alphabet: string, char: string): number {
  const idx = alphabet.indexOf(char);

  if (idx === -1) {
    throw new Error('Invalid character found: ' + char);
  }

  return idx;
}

function genSymKeyByData(symKeyData: Uint8Array) {
  let symKeyBlob: cryptoFramework.DataBlob = { data: symKeyData };
  let aesGenerator = cryptoFramework.createSymKeyGenerator('HMAC');
  let symKey = aesGenerator.convertKeySync(symKeyBlob);
  return symKey;
}

function doHmacBySync(steps: number, algorithm: HMACAlgorithm, message: string): Uint8Array {
  const byteLen = 8;
  let byteArray = new Uint8Array(byteLen);
  let tmp = steps; // wired TS feature
  for (let i = 0; i < byteLen; i++) {
    byteArray[byteLen - i-1] = tmp & 0xff;
    tmp = tmp >> 8;
  }
  let key = genSymKeyByData(base32Decode(message));
  let mac = cryptoFramework.createMac(algorithm);
  mac.initSync(key);
  mac.updateSync({ data: byteArray });
  let macResult = mac.doFinalSync();
  return macResult.data;
}

export function generateOTP(conf: TokenConfig, steps: number): number {
  try {
    let hash = doHmacBySync(steps, conf.TokenAlgorithm, conf.TokenSecret);
    const offset = hash[hash.length - 1] & 0xF;
    let truncatedHash = 0;
    for (let i = 0; i < 4; i++) {
      truncatedHash <<= 8;
      truncatedHash |= hash[offset + i];
    }
    truncatedHash &= 0x7FFFFFFF;
    return truncatedHash % Math.pow(10, conf.TokenDigits);
  } catch (err) {
    return 0;
  }
}

export function generateFileNameWithDate(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0'); // 月份从0开始，所以加1
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');

  const fileName = `${year}${month}${day}${hours}${minutes}${seconds}`;
  return fileName;
}

export function intArrayToString(input: ArrayBuffer): string {
  return buffer.from(input).toString()
}

export function stringToIntArray(input: string): Uint8Array {
  return Uint8Array.from(input, c => c.charCodeAt(0))
}

export function base32Encode(
  input: Uint8Array,
  variant: Base32Variant = 'RFC4648',
): string {
  let alphabet: string;
  let defaultPadding: boolean;

  switch (variant) {
    case 'RFC3548':
    case 'RFC4648':
      alphabet = RFC4648;
      defaultPadding = true;
      break;
    case 'RFC4648-HEX':
      alphabet = RFC4648_HEX;
      defaultPadding = true;
      break;
    case 'Crockford':
      alphabet = CROCKFORD;
      defaultPadding = false;
      break;
  // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
    default:
      throw new Error(`Unknown base32 variant: ${variant as string}`);
  }

  const padding = defaultPadding;
  const length = input.byteLength;
  const view = new Uint8Array(input);

  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < length; i++) {
    value = (value << 8) | view[i]!;
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  if (padding) {
    while (output.length % 8 !== 0) {
      output += '=';
    }
  }

  return output;
}

export function base32Decode(input: string, variant: Base32Variant = 'RFC4648'): Uint8Array {
  let alphabet: string;
  let cleanedInput: string;

  switch (variant) {
    case 'RFC3548':
    case 'RFC4648':
      alphabet = RFC4648;
      cleanedInput = input.toUpperCase().replace(/=+$/, '');
      break;
    case 'RFC4648-HEX':
      alphabet = RFC4648_HEX;
      cleanedInput = input.toUpperCase().replace(/=+$/, '');
      break;
    case 'Crockford':
      alphabet = CROCKFORD;
      cleanedInput = input.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
      break;
  // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
    default:
      throw new Error(`Unknown base32 variant: ${variant as string}`);
  }

  const length = cleanedInput.length;

  let bits = 0;
  let value = 0;

  let index = 0;
  const output = new Uint8Array(((length * 5) / 8) | 0);

  for (let i = 0; i < length; i++) {
    value = (value << 5) | readChar(alphabet, cleanedInput[i]!);
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return output;
}

const iconsArray: Array<string> =
  ['1and1', '1password', '23andme', 'adafruit', 'adguard', 'adobe', 'airbnb', 'airbrake', 'airtable', 'allegropl',
    'alwaysdata', 'amazon', 'amazonwebservices', 'angellist', 'animebytes', 'anonaddy', 'apache', 'apple', 'appveyor',
    'arenanet', 'atlantic_net', 'atlassian', 'avm', 'backblaze', 'battlenet', 'betterment', 'binance', 'bitbucket',
    'bitcoin', 'bitdefender', 'bitfinex', 'bitmex', 'bitpanda', 'bitstamp', 'bittrex', 'bitwala', 'bitwarden',
    'blockchain_info', 'bugcrowd', 'cexio', 'church_tools', 'cisco', 'cloudflare', 'cloud_download', 'cobranded',
    'codegiant', 'coinbase', 'coinjar', 'computerbase', 'connectwise_manage', 'cozycloud', 'crowdin', 'dashlane',
    'debian', 'degiro', 'denic', 'deutsche_bahn', 'diaspora', 'digidentity', 'digital_ocean', 'discord', 'discourse',
    'disroot', 'docker', 'docusign', 'dreamhost', 'dropbox', 'drupal', 'electronic_arts', 'email', 'epic_games', 'etsy',
    'eveonline', 'evernote', 'facebook', 'faceit', 'fanatical', 'fastmail', 'figma', 'fingerprint', 'finnair',
    'firefox', 'flight_takeoff', 'floatplane', 'friendica', 'fritz', 'gamepad', 'gandi', 'git', 'gitea', 'github',
    'gitlab', 'gmx', 'godaddy', 'gogs', 'google', 'govuk', 'grav', 'greenhost', 'hackerone', 'heroku', 'hetzner',
    'hitbtc', 'hmrc', 'home_assistant', 'hover', 'humblebundle', 'hurricane_electric', 'ibm', 'iconomi', 'ifttt', 'ing',
    'instagram', 'inwx', 'itchio', 'jagex', 'jetbrains', 'joomla', 'keeper', 'kickstarter', 'kraken', 'kucoin',
    'lastpass', 'librenms', 'lichess', 'linkedin', 'linode', 'liqui', 'livelyme', 'lobsters', 'localbitcoins',
    'localmonero', 'login_gov', 'logmein', 'mailbox', 'mailchimp', 'mailcow', 'mailgun', 'mailru', 'mapbox', 'mastodon',
    'matomo', 'mega', 'mercadolibre', 'microsoft', 'microsoft_teams', 'migadu', 'miles_and_more', 'mint', 'miraheze',
    'mixer', 'mongodb', 'mvpsnet', 'namecheap', 'namecom', 'nas', 'netcup', 'nextcloud', 'nintendo', 'no_starch_press',
    'npm', 'oculus', 'office', 'okta', 'online', 'openvz', 'opnsense', 'orcid', 'origin', 'ovh', 'packet',
    'parsecgaming', 'passwordstate', 'patreon', 'paypal', 'paysafecard', 'paywithprivacy', 'pcloud', 'phabricator',
    'phpmyadmin', 'pluralsight', 'plurk', 'posteo', 'pretix', 'prey', 'private_internet_access', 'protonmail',
    'proxmox', 'pushover', 'pypi', 'python_anywhere', 'rackspace', 'reddit', 'revolt', 'ripe_ncc', 'ripio', 'robinhood',
    'rocketbeanstv', 'rockstar', 'rss', 'sap', 'scaleway', 'school', 'sciebo', 'sentry', 'sevdesk', 'skrill', 'slack',
    'snapchat', 'sophos', 'sourceforge', 'squarespace', 'standardnotes', 'starcitizen', 'steam', 'stripe', 'sync',
    'synology', 'teahub', 'teamviewer', 'terminal', 'todoalojamiento', 'transip', 'trello', 'tumblr', 'turbotax',
    'tutanota', 'tuwien_ac_at', 'twilio', 'twitch', 'twitter', 'uber', 'ubisoft', 'ubnt', 'ubuntu_one', 'unity',
    'uphold', 'usaa', 'vagrant_cloud', 'vexxhost', 'vk', 'vultr', 'wallabag', 'wallet', 'wargaming', 'wasabi',
    'weclapp', 'wikimedia', 'wordpress', 'workplace', 'xero', 'xerox', 'xing', 'yandex_money', 'zapier', 'zendesk',
    'zoho', 'zoom'];
const iconsSet: HashSet<string> = new HashSet();
for (let item of iconsArray) {
  iconsSet.add(item);
}

export function getIconPathByIssuer(issuer: string): string {
  if (iconsSet.has(issuer.toLowerCase())) {
    return 'icons/token_image_' + issuer.toLowerCase() + '.svg';
  }
  return '';
}

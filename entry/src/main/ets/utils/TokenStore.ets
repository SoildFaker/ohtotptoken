import { KvManager } from "./KvManager";
import { TokenConfig } from "./TokenConfig";
import { HashMap, JSON } from "@kit.ArkTS";
import { RdbManager } from "./RdbManager";
import { common } from '@kit.AbilityKit';

export class TokenStore {
  private kvMgr: KvManager = KvManager.getInstance();
  private rdbMgr: RdbManager = RdbManager.getInstance();
  private token_uuids: string[] = [];
  private token_array: TokenConfig[] = [];
  private appCtx: common.UIAbilityContext | undefined = undefined;

  private static instance: TokenStore;

  private constructor() {

  }

  private async emitTokenChanged(): Promise<void> {
    this.appCtx?.eventHub.emit('onTokenChanged');
  }

  public static getInstance(): TokenStore {
    if (!TokenStore.instance) {
      TokenStore.instance = new TokenStore();
    }
    return TokenStore.instance;
  }

  public async initTokenStore(): Promise<void> {
    await this.kvMgr.initKvManager();
    this.token_uuids = await this.kvMgr.getStringArray('token_uuids') ?? [];
    this.appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
    for (let i = 0; i < this.token_uuids.length; i++) {
      let token = await this.queryToken(this.token_uuids[i]);
      this.token_array.push(token);
    }
  }

  public async getTokenUUIDs(): Promise<string[]> {
    return this.token_uuids;
  }

  public async getTokens(): Promise<TokenConfig[]> {
    return this.token_array;
  }

  public async queryToken(token_uuid: string): Promise<TokenConfig> {
    let token = await this.kvMgr.getValue<TokenConfig>(`token_${token_uuid}`);
    return token ?? new TokenConfig();
  }

  public async updateToken(token: TokenConfig): Promise<void> {
    await this.kvMgr.setValue<TokenConfig>(`token_${token.TokenUUID}`, token);
    if (!this.token_uuids.includes(token.TokenUUID)) {
      this.token_uuids.push(token.TokenUUID);
      this.token_array.push(token);
      await this.kvMgr.setStringArray('token_uuids', this.token_uuids);
      this.emitTokenChanged();
    } else {
      this.token_array[this.token_uuids.findIndex(uuid => uuid === token.TokenUUID)] = token;
    }
  }

  public async deleteToken(token_uuid: string): Promise<void> {
    this.token_uuids = this.token_uuids.filter(uuid => uuid !== token_uuid);
    await this.kvMgr.setStringArray('token_uuids', this.token_uuids);
    this.token_array = this.token_array.filter(token => token.TokenUUID !== token_uuid);
    this.kvMgr.deleteValue(token_uuid);
    this.emitTokenChanged();
  }
  //手动同步
  async DataSync(): Promise<void> {
    // 警告KV数据库同步会存在覆盖问题 因为目前token_uuids用的是一个key 多设备会有问题
    await this.kvMgr.DataSync();
  }
}
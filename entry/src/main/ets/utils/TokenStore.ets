import { KvManager } from "./KvManager";
import { TokenConfig } from "./TokenConfig";
import { HashMap, JSON } from "@kit.ArkTS";
import { RdbManager } from "./RdbManager";
import { common } from '@kit.AbilityKit';
import { faceDetector } from "@kit.CoreVisionKit";

export class TokenStore {
  private kvMgr: KvManager = KvManager.getInstance();
  private rdbMgr: RdbManager = RdbManager.getInstance();
  private token_uuids: string[] = [];
  private token_array: TokenConfig[] = [];
  private appCtx: common.UIAbilityContext | undefined = undefined;
  private init_done: boolean = false;
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
    if (this.init_done) {
      return;
    }
    await this.kvMgr.initKvManager();
    this.token_uuids = await this.kvMgr.getStringArray('token_uuids') ?? [];
    if (this.token_uuids.length == 0) {
      //尝试从旧缓存数据中恢复记录 兼容旧版本
      this.token_uuids = await this.kvMgr.getValue<string[]>('token_uuids') ?? [];
      await this.kvMgr.setStringArray('token_uuids', this.token_uuids);
    }
    this.appCtx = AppStorage.get<common.UIAbilityContext>('appContext') as common.UIAbilityContext;
    for (let i = 0; i < this.token_uuids.length; i++) {
      let token = await this.queryToken(this.token_uuids[i]);
      this.token_array.push(token);
    }
    this.sortTokens();
    this.init_done = true;
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

  public sortTokens(): void {
    this.token_array = this.token_array.sort((a, b) => a.RankScore - b.RankScore);
    this.token_uuids = this.token_array.map(token => token.TokenUUID);
    this.emitTokenChanged();
  }

  private async saveToken(token: TokenConfig): Promise<void> {
    await this.kvMgr.setValue<TokenConfig>(`token_${token.TokenUUID}`, token);
  }

  private async saveTokenPair(token1: TokenConfig, token2: TokenConfig): Promise<void> {
    await this.kvMgr.setValue<TokenConfig>(`token_${token1.TokenUUID}`, token1);
    await this.kvMgr.setValue<TokenConfig>(`token_${token2.TokenUUID}`, token2);
  }

  public async rearrangeToken(index: number, up: boolean): Promise<void> {
    const token = this.token_array[index];
    const score = token.RankScore;
    if (up) {
      if (index > 0) {
        const token_swap = this.token_array[index - 1];
        const token_uuid_swap = this.token_uuids[index - 1];
        this.token_array[index].RankScore = token_swap.RankScore;
        this.token_array[index - 1].RankScore = score;
        this.token_uuids[index - 1] = this.token_uuids[index];
        this.token_uuids[index] = token_uuid_swap;
        this.saveTokenPair(token, token_swap);
      }
    } else {
      if (index < this.token_array.length - 1) {
        const token_swap = this.token_array[index + 1];
        const token_uuid_swap = this.token_uuids[index + 1];
        this.token_array[index].RankScore = token_swap.RankScore;
        this.token_array[index + 1].RankScore = score;
        this.token_uuids[index + 1] = this.token_uuids[index];
        this.token_uuids[index] = token_uuid_swap;
        this.saveTokenPair(token, token_swap);
      }
    }
  }

  public async updateToken(token: TokenConfig): Promise<void> {
    let token_new = token;
    if (!this.token_uuids.includes(token_new.TokenUUID)) {
      if (this.token_array.length == 0) {
        token_new.RankScore = 1;//如果是第一次新增 就将rank设置为1
      } else {
        //否则设置成上一个新增的RankScore+1 但是这样有问题 改成寻找RankScore最大的+1
        let maxRankItem = this.token_array.reduce((max, current) => (max.RankScore > current.RankScore ? max : current))
        token_new.RankScore = maxRankItem.RankScore + 1;
      }
      this.token_uuids.push(token_new.TokenUUID);
      this.token_array.push(token_new);
      await this.kvMgr.setTokenUUID(token_new.TokenUUID);
    } else {
      this.token_array[this.token_uuids.findIndex(uuid => uuid === token_new.TokenUUID)] = token_new;
    }
    await this.saveToken(token_new);
    this.emitTokenChanged();
  }

  public async deleteToken(token_uuid: string): Promise<void> {
    await this.kvMgr.delTokenUUID(token_uuid);
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
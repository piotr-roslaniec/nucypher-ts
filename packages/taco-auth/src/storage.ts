import { AuthSignature, authSignatureSchema } from './index';

interface IStorage {
  getItem(key: string): string | null;

  setItem(key: string, value: string): void;
}

class BrowserStorage implements IStorage {
  public getItem(key: string): string | null {
    return localStorage.getItem(key);
  }

  public setItem(key: string, value: string): void {
    localStorage.setItem(key, value);
  }
}

class NodeStorage implements IStorage {
  private storage: Record<string, string> = {};

  public getItem(key: string): string | null {
    return this.storage[key] || null;
  }

  public setItem(key: string, value: string): void {
    this.storage[key] = value;
  }
}

export class LocalStorage {
  private storage: IStorage;

  constructor() {
    this.storage =
      typeof localStorage === 'undefined'
        ? new NodeStorage()
        : new BrowserStorage();
  }

  public getAuthSignature(key: string): AuthSignature | null {
    const asJson = this.storage.getItem(key);
    if (!asJson) {
      return null;
    }
    return authSignatureSchema.parse(JSON.parse(asJson));
  }

  public setAuthSignature(key: string, authSignature: AuthSignature): void {
    const asJson = JSON.stringify(authSignature);
    this.storage.setItem(key, asJson);
  }
}

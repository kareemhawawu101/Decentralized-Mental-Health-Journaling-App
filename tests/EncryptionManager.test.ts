import { describe, it, expect, beforeEach } from "vitest";
import {
  buffCV,
  uintCV,
  someCV,
  noneCV,
  stringAsciiCV,
  principalCV,
} from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_PUBLIC_KEY = 101;
const ERR_INVALID_ENCRYPTED_KEY = 102;
const ERR_KEY_NOT_FOUND = 103;
const ERR_KEY_ALREADY_EXISTS = 106;
const ERR_INVALID_KEY_TYPE = 104;
const ERR_INVALID_ENTRY_ID = 108;
const ERR_INVALID_IV = 114;
const ERR_INVALID_TAG = 115;
const ERR_AUTHORITY_NOT_VERIFIED = 111;
const ERR_INVALID_ROTATION_PERIOD = 118;

interface PublicKey {
  keyId: number;
  publicKey: Uint8Array;
  keyType: string;
  createdAt: number;
  status: boolean;
}

interface EntryKey {
  keyId: number;
  encryptedKey: Uint8Array;
  iv: Uint8Array;
  authTag: Uint8Array;
  mode: string;
  kdfSalt: Uint8Array;
  kdfIterations: number;
  expiresAt: number | null;
  rotatedAt: number;
  backupKey: Uint8Array | null;
}

interface RotationSchedule {
  nextRotation: number;
  period: number;
  autoRotate: boolean;
  lastRotated: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class EncryptionManagerMock {
  state: {
    nextKeyId: number;
    defaultKeyRotationPeriod: number;
    supportedEncryptionModes: string[];
    authorityContract: string | null;
    keyBackupEnabled: boolean;
    userPublicKeys: Map<string, PublicKey>;
    entryEncryptionKeys: Map<string, EntryKey>;
    keyRotationSchedule: Map<string, RotationSchedule>;
    keyAccessLog: Map<
      string,
      { accessedAt: number; keyId: number; success: boolean }
    >;
  } = {
    nextKeyId: 0,
    defaultKeyRotationPeriod: 365,
    supportedEncryptionModes: ["AES-256-GCM", "CHACHA20-POLY1305"],
    authorityContract: null,
    keyBackupEnabled: true,
    userPublicKeys: new Map(),
    entryEncryptionKeys: new Map(),
    keyRotationSchedule: new Map(),
    keyAccessLog: new Map(),
  };
  blockHeight: number = 1000;
  caller: string = "ST1USER";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextKeyId: 0,
      defaultKeyRotationPeriod: 365,
      supportedEncryptionModes: ["AES-256-GCM", "CHACHA20-POLY1305"],
      authorityContract: null,
      keyBackupEnabled: true,
      userPublicKeys: new Map(),
      entryEncryptionKeys: new Map(),
      keyRotationSchedule: new Map(),
      keyAccessLog: new Map(),
    };
    this.blockHeight = 1000;
    this.caller = "ST1USER";
  }

  private getEntryKey(user: string, entryId: number): string {
    return `${user}-${entryId}`;
  }

  private getRotationKey(user: string, keyId: number): string {
    return `${user}-${keyId}`;
  }

  private getAccessLogKey(
    user: string,
    entryId: number,
    accessor: string
  ): string {
    return `${user}-${entryId}-${accessor}`;
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78")
      return { ok: false, value: false };
    if (this.state.authorityContract !== null)
      return { ok: false, value: false };
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setDefaultKeyRotationPeriod(newPeriod: number): Result<boolean> {
    if (newPeriod <= 0) return { ok: false, value: false };
    if (!this.state.authorityContract) return { ok: false, value: false };
    this.state.defaultKeyRotationPeriod = newPeriod;
    return { ok: true, value: true };
  }

  registerPublicKey(publicKey: Uint8Array, keyType: string): Result<number> {
    if (publicKey.length !== 64) return { ok: false, value: 101 };
    if (!["ed25519", "secp256k1"].includes(keyType))
      return { ok: false, value: 104 };
    if (this.state.userPublicKeys.has(this.caller))
      return { ok: false, value: 106 };

    const keyId = this.state.nextKeyId;
    this.state.userPublicKeys.set(this.caller, {
      keyId,
      publicKey,
      keyType,
      createdAt: this.blockHeight,
      status: true,
    });
    this.state.nextKeyId++;
    return { ok: true, value: keyId };
  }

  getUserPublicKey(user: string): PublicKey | null {
    return this.state.userPublicKeys.get(user) || null;
  }

  storeEntryEncryptionKey(
    entryId: number,
    encryptedKey: Uint8Array,
    iv: Uint8Array,
    authTag: Uint8Array,
    mode: string,
    kdfSalt: Uint8Array,
    kdfIterations: number,
    expiresAt: number | null,
    backupKey: Uint8Array | null
  ): Result<number> {
    if (entryId < 0) return { ok: false, value: 108 };
    if (encryptedKey.length !== 128) return { ok: false, value: 102 };
    if (iv.length !== 12) return { ok: false, value: 114 };
    if (authTag.length !== 16) return { ok: false, value: 115 };
    if (!this.state.supportedEncryptionModes.includes(mode))
      return { ok: false, value: 112 };
    if (!this.state.userPublicKeys.has(this.caller))
      return { ok: false, value: 103 };
    const key = this.getEntryKey(this.caller, entryId);
    if (this.state.entryEncryptionKeys.has(key))
      return { ok: false, value: 106 };
    if (backupKey && backupKey.length !== 128) return { ok: false, value: 102 };

    const keyId = this.state.nextKeyId;
    this.state.entryEncryptionKeys.set(key, {
      keyId,
      encryptedKey,
      iv,
      authTag,
      mode,
      kdfSalt,
      kdfIterations,
      expiresAt,
      rotatedAt: this.blockHeight,
      backupKey,
    });
    this.state.keyRotationSchedule.set(
      this.getRotationKey(this.caller, keyId),
      {
        nextRotation: this.blockHeight + this.state.defaultKeyRotationPeriod,
        period: this.state.defaultKeyRotationPeriod,
        autoRotate: true,
        lastRotated: this.blockHeight,
      }
    );
    this.state.nextKeyId++;
    return { ok: true, value: keyId };
  }

  getEntryEncryptionKey(user: string, entryId: number): EntryKey | null {
    return (
      this.state.entryEncryptionKeys.get(this.getEntryKey(user, entryId)) ||
      null
    );
  }

  rotateEntryKey(
    entryId: number,
    newEncryptedKey: Uint8Array,
    newIv: Uint8Array,
    newAuthTag: Uint8Array,
    newBackupKey: Uint8Array | null
  ): Result<boolean> {
    if (
      newEncryptedKey.length !== 128 ||
      newIv.length !== 12 ||
      newAuthTag.length !== 16
    )
      return { ok: false, value: false };
    if (newBackupKey && newBackupKey.length !== 128)
      return { ok: false, value: false };
    const key = this.getEntryKey(this.caller, entryId);
    const existing = this.state.entryEncryptionKeys.get(key);
    if (!existing) return { ok: false, value: false };

    this.state.entryEncryptionKeys.set(key, {
      ...existing,
      encryptedKey: newEncryptedKey,
      iv: newIv,
      authTag: newAuthTag,
      rotatedAt: this.blockHeight,
      backupKey: newBackupKey,
    });
    const rotKey = this.getRotationKey(this.caller, existing.keyId);
    const schedule = this.state.keyRotationSchedule.get(rotKey);
    if (schedule) {
      this.state.keyRotationSchedule.set(rotKey, {
        ...schedule,
        nextRotation: this.blockHeight + schedule.period,
        lastRotated: this.blockHeight,
      });
    }
    return { ok: true, value: true };
  }

  logKeyAccess(
    entryId: number,
    accessor: string,
    success: boolean
  ): Result<boolean> {
    const key = this.getEntryKey(this.caller, entryId);
    if (!this.state.entryEncryptionKeys.has(key))
      return { ok: false, value: false };
    const entryKey = this.state.entryEncryptionKeys.get(key)!;
    this.state.keyAccessLog.set(
      this.getAccessLogKey(this.caller, entryId, accessor),
      {
        accessedAt: this.blockHeight,
        keyId: entryKey.keyId,
        success,
      }
    );
    return { ok: true, value: true };
  }

  checkKeyRotationDue(user: string, keyId: number): Result<boolean> {
    const rotKey = this.getRotationKey(user, keyId);
    const schedule = this.state.keyRotationSchedule.get(rotKey);
    if (!schedule) return { ok: false, value: 103 };
    return { ok: true, value: this.blockHeight >= schedule.nextRotation };
  }
}

describe("EncryptionManager", () => {
  let contract: EncryptionManagerMock;

  beforeEach(() => {
    contract = new EncryptionManagerMock();
    contract.reset();
    contract.setAuthorityContract("ST2AUTH");
  });

  it("registers public key successfully", () => {
    const pubKey = new Uint8Array(64);
    const result = contract.registerPublicKey(pubKey, "ed25519");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const key = contract.getUserPublicKey("ST1USER");
    expect(key?.keyType).toBe("ed25519");
  });

  it("rejects duplicate public key", () => {
    const pubKey = new Uint8Array(64);
    contract.registerPublicKey(pubKey, "ed25519");
    const result = contract.registerPublicKey(pubKey, "secp256k1");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_KEY_ALREADY_EXISTS);
  });

  it("stores entry encryption key successfully", () => {
    contract.registerPublicKey(new Uint8Array(64), "ed25519");
    const encKey = new Uint8Array(128);
    const iv = new Uint8Array(12);
    const tag = new Uint8Array(16);
    const salt = new Uint8Array(32);
    const result = contract.storeEntryEncryptionKey(
      0,
      encKey,
      iv,
      tag,
      "AES-256-GCM",
      salt,
      100000,
      null,
      null
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);
  });

  it("rejects unsupported encryption mode", () => {
    contract.registerPublicKey(new Uint8Array(64), "ed25519");
    const encKey = new Uint8Array(128);
    const iv = new Uint8Array(12);
    const tag = new Uint8Array(16);
    const salt = new Uint8Array(32);
    const result = contract.storeEntryEncryptionKey(
      0,
      encKey,
      iv,
      tag,
      "INVALID-MODE",
      salt,
      100000,
      null,
      null
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(112);
  });

  it("rotates entry key successfully", () => {
    contract.registerPublicKey(new Uint8Array(64), "ed25519");
    const encKey = new Uint8Array(128);
    const iv = new Uint8Array(12);
    const tag = new Uint8Array(16);
    const salt = new Uint8Array(32);
    contract.storeEntryEncryptionKey(
      0,
      encKey,
      iv,
      tag,
      "AES-256-GCM",
      salt,
      100000,
      null,
      null
    );
    const newEncKey = new Uint8Array(128);
    const newIv = new Uint8Array(12);
    const newTag = new Uint8Array(16);
    const result = contract.rotateEntryKey(0, newEncKey, newIv, newTag, null);
    expect(result.ok).toBe(true);
  });

  it("logs key access", () => {
    contract.registerPublicKey(new Uint8Array(64), "ed25519");
    const encKey = new Uint8Array(128);
    const iv = new Uint8Array(12);
    const tag = new Uint8Array(16);
    const salt = new Uint8Array(32);
    contract.storeEntryEncryptionKey(
      0,
      encKey,
      iv,
      tag,
      "AES-256-GCM",
      salt,
      100000,
      null,
      null
    );
    const result = contract.logKeyAccess(0, "ST3THERAPIST", true);
    expect(result.ok).toBe(true);
  });

  it("checks key rotation due", () => {
    contract.registerPublicKey(new Uint8Array(64), "ed25519");
    const encKey = new Uint8Array(128);
    const iv = new Uint8Array(12);
    const tag = new Uint8Array(16);
    const salt = new Uint8Array(32);
    const keyId = contract.storeEntryEncryptionKey(
      0,
      encKey,
      iv,
      tag,
      "AES-256-GCM",
      salt,
      100000,
      null,
      null
    ).value;
    contract.blockHeight = 2000;
    const result = contract.checkKeyRotationDue("ST1USER", keyId);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });
});

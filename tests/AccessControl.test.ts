import { describe, it, expect, beforeEach } from "vitest";
import { uintCV, someCV, noneCV, principalCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_ENTRY_NOT_FOUND = 101;
const ERR_ALREADY_GRANTED = 103;
const ERR_NOT_GRANTED = 104;
const ERR_INVALID_EXPIRY = 105;
const ERR_PERMISSION_EXPIRED = 106;
const ERR_INVALID_LEVEL = 107;
const ERR_THERAPIST_NOT_VERIFIED = 108;
const ERR_MAX_SHARES_EXCEEDED = 110;
const ERR_INVALID_THERAPIST = 113;
const ERR_AUTHORITY_NOT_VERIFIED = 115;
const ERR_INVALID_MAX_SHARES = 116;

interface Permission {
  permissionId: number;
  level: number;
  grantedAt: number;
  expiresAt: number | null;
  status: boolean;
  lastAccessed: number | null;
}

interface PermissionHistory {
  user: string;
  entryId: number;
  therapist: string;
  oldLevel: number;
  newLevel: number;
  updatedAt: number;
  updater: string;
}

interface Therapist {
  verified: boolean;
  licenseHash: Uint8Array;
  verifiedAt: number;
  status: boolean;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class AccessControlMock {
  state: {
    nextPermissionId: number;
    maxSharesPerEntry: number;
    defaultPermissionLevel: number;
    authorityContract: string | null;
    auditLogEnabled: boolean;
    permissions: Map<string, Permission>;
    permissionHistory: Map<number, PermissionHistory>;
    therapistRegistry: Map<string, Therapist>;
    userShareCounts: Map<string, number>;
  } = {
    nextPermissionId: 0,
    maxSharesPerEntry: 10,
    defaultPermissionLevel: 1,
    authorityContract: null,
    auditLogEnabled: true,
    permissions: new Map(),
    permissionHistory: new Map(),
    therapistRegistry: new Map(),
    userShareCounts: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1USER";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextPermissionId: 0,
      maxSharesPerEntry: 10,
      defaultPermissionLevel: 1,
      authorityContract: null,
      auditLogEnabled: true,
      permissions: new Map(),
      permissionHistory: new Map(),
      therapistRegistry: new Map(),
      userShareCounts: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1USER";
  }

  private getPermissionKey(user: string, entryId: number, therapist: string): string {
    return `${user}-${entryId}-${therapist}`;
  }

  private getShareCountKey(user: string, entryId: number): string {
    return `${user}-${entryId}`;
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") {
      return { ok: false, value: false };
    }
    if (this.state.authorityContract !== null) {
      return { ok: false, value: false };
    }
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setMaxSharesPerEntry(newMax: number): Result<boolean> {
    if (newMax <= 0) return { ok: false, value: false };
    if (!this.state.authorityContract) return { ok: false, value: false };
    this.state.maxSharesPerEntry = newMax;
    return { ok: true, value: true };
  }

  verifyTherapist(therapist: string, licenseHash: Uint8Array): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    if (licenseHash.length !== 32) return { ok: false, value: false };
    this.state.therapistRegistry.set(therapist, {
      verified: true,
      licenseHash,
      verifiedAt: this.blockHeight,
      status: true,
    });
    return { ok: true, value: true };
  }

  grantPermission(
    entryId: number,
    therapist: string,
    level: number,
    expiresAt: number | null
  ): Result<number> {
    const user = this.caller;
    if (entryId < 0) return { ok: false, value: 112 };
    if (therapist === this.caller || therapist === "SP000000000000000000002Q6VF78") return { ok: false, value: 113 };
    if (level < 1 || level > 3) return { ok: false, value: 107 };
    if (expiresAt !== null && expiresAt <= this.blockHeight) return { ok: false, value: 105 };
    const countKey = this.getShareCountKey(user, entryId);
    const currentCount = this.state.userShareCounts.get(countKey) || 0;
    if (currentCount >= this.state.maxSharesPerEntry) return { ok: false, value: 110 };
    const key = this.getPermissionKey(user, entryId, therapist);
    if (this.state.permissions.has(key)) return { ok: false, value: 103 };
    if (!this.state.therapistRegistry.has(therapist)) return { ok: false, value: 108 };

    const permissionId = this.state.nextPermissionId;
    this.state.permissions.set(key, {
      permissionId,
      level,
      grantedAt: this.blockHeight,
      expiresAt,
      status: true,
      lastAccessed: null,
    });
    this.state.userShareCounts.set(countKey, currentCount + 1);
    this.state.nextPermissionId++;
    if (this.state.auditLogEnabled) {
      this.state.permissionHistory.set(permissionId, {
        user,
        entryId,
        therapist,
        oldLevel: 0,
        newLevel: level,
        updatedAt: this.blockHeight,
        updater: this.caller,
      });
    }
    return { ok: true, value: permissionId };
  }

  getPermission(user: string, entryId: number, therapist: string): Permission | null {
    return this.state.permissions.get(this.getPermissionKey(user, entryId, therapist)) || null;
  }

  updatePermissionLevel(entryId: number, therapist: string, newLevel: number): Result<boolean> {
    const user = this.caller;
    if (newLevel < 1 || newLevel > 3) return { ok: false, value: false };
    const key = this.getPermissionKey(user, entryId, therapist);
    const permission = this.state.permissions.get(key);
    if (!permission) return { ok: false, value: false };
    if (!permission.status) return { ok: false, value: false };

    const updated = { ...permission, level: newLevel, lastAccessed: this.blockHeight };
    this.state.permissions.set(key, updated);
    if (this.state.auditLogEnabled) {
      this.state.permissionHistory.set(permission.permissionId, {
        user,
        entryId,
        therapist,
        oldLevel: permission.level,
        newLevel,
        updatedAt: this.blockHeight,
        updater: this.caller,
      });
    }
    return { ok: true, value: true };
  }

  revokePermission(entryId: number, therapist: string): Result<boolean> {
    const user = this.caller;
    const key = this.getPermissionKey(user, entryId, therapist);
    const permission = this.state.permissions.get(key);
    if (!permission) return { ok: false, value: false };
    if (!permission.status) return { ok: false, value: false };

    this.state.permissions.set(key, { ...permission, status: false, lastAccessed: this.blockHeight });
    const countKey = this.getShareCountKey(user, entryId);
    const count = this.state.userShareCounts.get(countKey) || 0;
    this.state.userShareCounts.set(countKey, count - 1);
    if (this.state.auditLogEnabled) {
      this.state.permissionHistory.set(permission.permissionId, {
        user,
        entryId,
        therapist,
        oldLevel: permission.level,
        newLevel: 0,
        updatedAt: this.blockHeight,
        updater: this.caller,
      });
    }
    return { ok: true, value: true };
  }

  checkAccess(user: string, entryId: number, therapist: string): Result<number> {
    const key = this.getPermissionKey(user, entryId, therapist);
    const permission = this.state.permissions.get(key);
    if (!permission) return { ok: false, value: 104 };
    if (!permission.status) return { ok: false, value: 104 };
    if (permission.expiresAt !== null && permission.expiresAt <= this.blockHeight) {
      return { ok: false, value: 106 };
    }
    this.state.permissions.set(key, { ...permission, lastAccessed: this.blockHeight });
    return { ok: true, value: permission.level };
  }

  getActiveShares(user: string, entryId: number): Result<number> {
    return { ok: true, value: this.state.userShareCounts.get(this.getShareCountKey(user, entryId)) || 0 };
  }
}

describe("AccessControl", () => {
  let contract: AccessControlMock;

  beforeEach(() => {
    contract = new AccessControlMock();
    contract.reset();
    contract.setAuthorityContract("ST2AUTH");
    contract.verifyTherapist("ST3THERAPIST", new Uint8Array(32));
  });

  it("grants permission successfully", () => {
    const result = contract.grantPermission(0, "ST3THERAPIST", 2, null);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const perm = contract.getPermission("ST1USER", 0, "ST3THERAPIST");
    expect(perm?.level).toBe(2);
    expect(perm?.status).toBe(true);
  });

  it("rejects duplicate permission", () => {
    contract.grantPermission(0, "ST3THERAPIST", 2, null);
    const result = contract.grantPermission(0, "ST3THERAPIST", 1, null);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ALREADY_GRANTED);
  });

  it("rejects unverified therapist", () => {
    const result = contract.grantPermission(0, "ST4UNVERIFIED", 2, null);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_THERAPIST_NOT_VERIFIED);
  });

  it("updates permission level", () => {
    contract.grantPermission(0, "ST3THERAPIST", 1, null);
    const result = contract.updatePermissionLevel(0, "ST3THERAPIST", 3);
    expect(result.ok).toBe(true);
    const perm = contract.getPermission("ST1USER", 0, "ST3THERAPIST");
    expect(perm?.level).toBe(3);
  });

  it("revokes permission", () => {
    contract.grantPermission(0, "ST3THERAPIST", 2, null);
    const result = contract.revokePermission(0, "ST3THERAPIST");
    expect(result.ok).toBe(true);
    const perm = contract.getPermission("ST1USER", 0, "ST3THERAPIST");
    expect(perm?.status).toBe(false);
  });

  it("checks access successfully", () => {
    contract.grantPermission(0, "ST3THERAPIST", 2, 200);
    const result = contract.checkAccess("ST1USER", 0, "ST3THERAPIST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });
  
  it("enforces max shares per entry", () => {
    contract.setMaxSharesPerEntry(1);
    contract.grantPermission(0, "ST3THERAPIST", 2, null);
    contract.verifyTherapist("ST4OTHER", new Uint8Array(32));
    const result = contract.grantPermission(0, "ST4OTHER", 1, null);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_SHARES_EXCEEDED);
  });

  it("tracks active shares", () => {
    contract.grantPermission(0, "ST3THERAPIST", 2, null);
    const result = contract.getActiveShares("ST1USER", 0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);
  });
});
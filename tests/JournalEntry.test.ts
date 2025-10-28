import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV, boolCV, buffCV, listCV, stringAsciiCV, principalCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_HASH = 101;
const ERR_ENTRY_NOT_FOUND = 102;
const ERR_INVALID_MOOD_RATING = 103;
const ERR_INVALID_CONTENT = 104;
const ERR_ENTRY_ALREADY_EXISTS = 106;
const ERR_MAX_ENTRIES_EXCEEDED = 107;
const ERR_INVALID_CATEGORY = 112;
const ERR_INVALID_TAG = 113;
const ERR_INVALID_SHARE_LEVEL = 120;
const ERR_INVALID_UPDATE_PARAM = 115;
const ERR_AUTHORITY_NOT_VERIFIED = 116;
const ERR_INVALID_MAX_ENTRIES = 117;
const ERR_PERMISSION_DENIED = 109;

interface Entry {
  encryptedContent: Uint8Array;
  timestamp: number;
  moodRating: number;
  contentHash: Uint8Array;
  category: string;
  tags: string[];
  status: boolean;
  shareLevel: number;
}

interface EntryUpdate {
  updateTimestamp: number;
  updater: string;
  previousHash: Uint8Array;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class JournalEntryMock {
  state: {
    nextEntryId: number;
    maxEntriesPerUser: number;
    retentionPeriod: number;
    authorityContract: string | null;
    encryptionScheme: string;
    entryFee: number;
    entries: Map<string, Entry>;
    entryUpdates: Map<string, EntryUpdate>;
    userEntryCounts: Map<string, number>;
    sharedAccess: Map<string, boolean>;
  } = {
    nextEntryId: 0,
    maxEntriesPerUser: 1000,
    retentionPeriod: 365,
    authorityContract: null,
    encryptionScheme: "AES-256-GCM",
    entryFee: 10,
    entries: new Map(),
    entryUpdates: new Map(),
    userEntryCounts: new Map(),
    sharedAccess: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextEntryId: 0,
      maxEntriesPerUser: 1000,
      retentionPeriod: 365,
      authorityContract: null,
      encryptionScheme: "AES-256-GCM",
      entryFee: 10,
      entries: new Map(),
      entryUpdates: new Map(),
      userEntryCounts: new Map(),
      sharedAccess: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
    this.stxTransfers = [];
  }

  private getEntryKey(user: string, id: number): string {
    return `${user}-${id}`;
  }

  private getAccessKey(user: string, id: number, therapist: string): string {
    return `${user}-${id}-${therapist}`;
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

  setMaxEntriesPerUser(newMax: number): Result<boolean> {
    if (newMax <= 0) return { ok: false, value: false };
    if (!this.state.authorityContract) return { ok: false, value: false };
    this.state.maxEntriesPerUser = newMax;
    return { ok: true, value: true };
  }

  setEntryFee(newFee: number): Result<boolean> {
    if (!this.state.authorityContract) return { ok: false, value: false };
    this.state.entryFee = newFee;
    return { ok: true, value: true };
  }

  addEntry(
    encryptedContent: Uint8Array,
    moodRating: number,
    contentHash: Uint8Array,
    category: string,
    tags: string[],
    status: boolean,
    shareLevel: number
  ): Result<number> {
    const user = this.caller;
    const currentCount = this.state.userEntryCounts.get(user) || 0;
    if (currentCount >= this.state.maxEntriesPerUser) return { ok: false, value: ERR_MAX_ENTRIES_EXCEEDED };
    if (encryptedContent.length === 0) return { ok: false, value: ERR_INVALID_CONTENT };
    if (moodRating < 1 || moodRating > 10) return { ok: false, value: ERR_INVALID_MOOD_RATING };
    if (contentHash.length !== 32) return { ok: false, value: ERR_INVALID_HASH };
    if (category.length === 0 || category.length > 50) return { ok: false, value: ERR_INVALID_CATEGORY };
    for (const tag of tags) {
      if (tag.length === 0 || tag.length > 20) return { ok: false, value: ERR_INVALID_TAG };
    }
    if (shareLevel > 3) return { ok: false, value: ERR_INVALID_SHARE_LEVEL };
    const entryId = this.state.nextEntryId;
    const key = this.getEntryKey(user, entryId);
    if (this.state.entries.has(key)) return { ok: false, value: ERR_ENTRY_ALREADY_EXISTS };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };

    this.stxTransfers.push({ amount: this.state.entryFee, from: this.caller, to: this.state.authorityContract });

    const entry: Entry = {
      encryptedContent,
      timestamp: this.blockHeight,
      moodRating,
      contentHash,
      category,
      tags,
      status,
      shareLevel,
    };
    this.state.entries.set(key, entry);
    this.state.userEntryCounts.set(user, currentCount + 1);
    this.state.nextEntryId++;
    return { ok: true, value: entryId };
  }

  getEntry(user: string, id: number): Entry | null {
    return this.state.entries.get(this.getEntryKey(user, id)) || null;
  }

  updateEntry(
    entryId: number,
    newEncryptedContent: Uint8Array,
    newMoodRating: number,
    newContentHash: Uint8Array
  ): Result<boolean> {
    const user = this.caller;
    const key = this.getEntryKey(user, entryId);
    const entry = this.state.entries.get(key);
    if (!entry) return { ok: false, value: false };
    if (user !== this.caller) return { ok: false, value: false };
    if (newEncryptedContent.length === 0) return { ok: false, value: false };
    if (newMoodRating < 1 || newMoodRating > 10) return { ok: false, value: false };
    if (newContentHash.length !== 32) return { ok: false, value: false };

    const updated: Entry = {
      ...entry,
      encryptedContent: newEncryptedContent,
      timestamp: this.blockHeight,
      moodRating: newMoodRating,
      contentHash: newContentHash,
    };
    this.state.entries.set(key, updated);
    this.state.entryUpdates.set(key, {
      updateTimestamp: this.blockHeight,
      updater: this.caller,
      previousHash: entry.contentHash,
    });
    return { ok: true, value: true };
  }

  grantAccess(entryId: number, therapist: string): Result<boolean> {
    const user = this.caller;
    const entryKey = this.getEntryKey(user, entryId);
    if (!this.state.entries.has(entryKey)) return { ok: false, value: false };
    const accessKey = this.getAccessKey(user, entryId, therapist);
    if (this.state.sharedAccess.has(accessKey)) return { ok: false, value: false };
    this.state.sharedAccess.set(accessKey, true);
    return { ok: true, value: true };
  }

  revokeAccess(entryId: number, therapist: string): Result<boolean> {
    const user = this.caller;
    const entryKey = this.getEntryKey(user, entryId);
    if (!this.state.entries.has(entryKey)) return { ok: false, value: false };
    const accessKey = this.getAccessKey(user, entryId, therapist);
    if (!this.state.sharedAccess.has(accessKey)) return { ok: false, value: false };
    this.state.sharedAccess.delete(accessKey);
    return { ok: true, value: true };
  }

  deleteEntry(entryId: number): Result<boolean> {
    const user = this.caller;
    const key = this.getEntryKey(user, entryId);
    if (!this.state.entries.has(key)) return { ok: false, value: false };
    this.state.entries.delete(key);
    this.state.entryUpdates.delete(key);
    const count = this.state.userEntryCounts.get(user) || 0;
    this.state.userEntryCounts.set(user, count - 1);
    return { ok: true, value: true };
  }

  getTotalEntries(): Result<number> {
    return { ok: true, value: this.state.nextEntryId };
  }

  checkEntryExistence(user: string, id: number): Result<boolean> {
    return { ok: true, value: this.state.entries.has(this.getEntryKey(user, id)) };
  }
}

describe("JournalEntry", () => {
  let contract: JournalEntryMock;

  beforeEach(() => {
    contract = new JournalEntryMock();
    contract.reset();
  });

  it("adds an entry successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    const result = contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);

    const entry = contract.getEntry("ST1TEST", 0);
    expect(entry?.moodRating).toBe(5);
    expect(entry?.category).toBe("daily");
    expect(entry?.tags).toEqual(["mood"]);
    expect(entry?.status).toBe(true);
    expect(entry?.shareLevel).toBe(1);
    expect(contract.stxTransfers).toEqual([{ amount: 10, from: "ST1TEST", to: "ST2TEST" }]);
  });

  it("rejects duplicate entry id", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    contract.state.nextEntryId = 0; // Force duplicate
    const result = contract.addEntry(content, 6, hash, "weekly", ["thought"], false, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ENTRY_ALREADY_EXISTS);
  });

  it("rejects invalid mood rating", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    const result = contract.addEntry(content, 0, hash, "daily", ["mood"], true, 1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_MOOD_RATING);
  });

  it("rejects entry without authority contract", () => {
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    const result = contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUTHORITY_NOT_VERIFIED);
  });

  it("rejects invalid category", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    const result = contract.addEntry(content, 5, hash, "", ["mood"], true, 1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_CATEGORY);
  });

  it("updates an entry successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    const newContent = new Uint8Array(15);
    const newHash = new Uint8Array(32);
    const result = contract.updateEntry(0, newContent, 7, newHash);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const entry = contract.getEntry("ST1TEST", 0);
    expect(entry?.moodRating).toBe(7);
  });

  it("rejects update for non-existent entry", () => {
    contract.setAuthorityContract("ST2TEST");
    const newContent = new Uint8Array(15);
    const newHash = new Uint8Array(32);
    const result = contract.updateEntry(99, newContent, 7, newHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("grants access successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    const result = contract.grantAccess(0, "ST3THERAPIST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("revokes access successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    contract.grantAccess(0, "ST3THERAPIST");
    const result = contract.revokeAccess(0, "ST3THERAPIST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("deletes an entry successfully", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    const result = contract.deleteEntry(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getEntry("ST1TEST", 0)).toBeNull();
  });

  it("returns correct total entries", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    contract.addEntry(content, 6, hash, "weekly", ["thought"], false, 2);
    const result = contract.getTotalEntries();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks entry existence correctly", () => {
    contract.setAuthorityContract("ST2TEST");
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    const result = contract.checkEntryExistence("ST1TEST", 0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const result2 = contract.checkEntryExistence("ST1TEST", 99);
    expect(result2.ok).toBe(true);
    expect(result2.value).toBe(false);
  });

  it("rejects entry addition with max exceeded", () => {
    contract.setAuthorityContract("ST2TEST");
    contract.state.maxEntriesPerUser = 1;
    const content = new Uint8Array(10);
    const hash = new Uint8Array(32);
    contract.addEntry(content, 5, hash, "daily", ["mood"], true, 1);
    const result = contract.addEntry(content, 6, hash, "weekly", ["thought"], false, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_ENTRIES_EXCEEDED);
  });

  it("sets authority contract successfully", () => {
    const result = contract.setAuthorityContract("ST2TEST");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2TEST");
  });

  it("rejects invalid authority contract", () => {
    const result = contract.setAuthorityContract("SP000000000000000000002Q6VF78");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });
});
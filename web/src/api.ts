/** Thin JSON fetch wrapper; every API error surfaces as a thrown Error. */

/** Fired when the API answers 401, so the session can be re-read once. */
export const UNAUTHORIZED_EVENT = "portal:unauthorized";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    credentials: "same-origin",
    ...init,
  });
  const body = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (res.status === 401) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  return body;
}

export interface Guild {
  id: string;
  name: string;
  /** Full CDN URL. */
  icon?: string;
}

export interface Me {
  user: { id: string; username: string; avatarUrl?: string } | null;
  guilds?: Guild[];
  devLogin: boolean;
  discordConfigured: boolean;
}

export interface ImportChannel {
  discordId: string;
  name: string;
  topic?: string;
  category?: string;
  kind?: "voice";
  /** Gated on Discord; imports as a key-gated private channel. */
  private?: boolean;
  bridgeable: boolean;
  /** The bot lacks Manage Webhooks here, so a live bridge could not post into Discord. */
  botMissingWebhook?: boolean;
  bridge: boolean;
  selected: boolean;
  history: boolean;
  historyImported?: number;
  historyDoneAt?: number;
  publishedAt?: number;
  bridgeId?: string;
  /** Why a requested live bridge was not wired (e.g. the channel was already bridged). */
  bridgeSkipped?: string;
}

/** The import plan as the API returns it (see crates/portal/src/import_plan.rs). */
export interface ImportPlanView {
  guild: { id: string; name: string; description?: string; iconUrl?: string };
  communityName: string;
  memberCount?: number;
  emojis: Array<{ id: string; name: string }>;
  channels: ImportChannel[];
  roles: Array<{ discordId: string; name: string; dropped: string[]; publishedAt?: number }>;
  skipped: Array<{ kind: string; name: string; reason: string }>;
  checkpoints?: { communityIdHex?: string; ownerPkHex?: string; emojiPackAddress?: string };
}

/** An unsigned seal template the owner signs in-browser (NIP-07 shape). */
export interface OwnerSignTemplate {
  purpose: string;
  template: { kind: number; content: string; tags: string[][]; created_at: number };
}

export interface ImportStatus {
  importId: string;
  status: "previewed" | "awaiting_sigs" | "minting" | "publishing" | "wiring" | "history" | "done" | "failed";
  statusDetail?: string | null;
  plan: ImportPlanView;
  communityId?: string | null;
  inviteUrl?: string;
}

export type BridgeStatus = "draft" | "pending_confirm" | "active" | "paused" | "severed" | (string & {});

export interface BridgeSummary {
  bridge_id: string;
  status: BridgeStatus;
  status_detail?: string;
  community_name?: string;
  community_id?: string;
  discord_guild_id?: string;
  discord_guild_name?: string;
  discord_channel_id?: string;
  discord_channel_name?: string;
  concord_channel_id?: string;
  concord_channel_name?: string;
  confirm_code?: string;
  primary_pk?: string;
  created_at?: string;
  bridged_count: string;
  /** Whether the manager is running it right now (zipped in from the `live` array). */
  live?: boolean;
}

export async function listBridges(): Promise<BridgeSummary[]> {
  const res = await api<{ bridges: BridgeSummary[]; live?: boolean[] }>("/api/bridges");
  return res.bridges.map((b, i) => ({ ...b, live: res.live?.[i] }));
}

/** Thin JSON fetch wrapper; every API error surfaces as a thrown Error. */

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    credentials: "same-origin",
    ...init,
  });
  const body = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  return body;
}

export interface Me {
  user: { id: string; username: string; avatarUrl?: string } | null;
  guilds?: Array<{ id: string; name: string; icon?: string }>;
  devLogin: boolean;
  discordConfigured: boolean;
}

/** The import plan as the API returns it (see portal/src/importPlan.ts). */
export interface ImportPlanView {
  guild: { id: string; name: string; description?: string; iconUrl?: string };
  communityName: string;
  memberCount?: number;
  /** Always true since history stopped being gated on server size; unread. */
  historyAllowed: boolean;
  emojis: Array<{ id: string; name: string }>;
  channels: Array<{
    discordId: string;
    name: string;
    category?: string;
    kind?: "voice";
    bridgeable: boolean;
    bridge: boolean;
    selected: boolean;
    history: boolean;
    historyImported?: number;
    historyDoneAt?: number;
    publishedAt?: number;
    bridgeId?: string;
  }>;
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

export interface BridgeSummary {
  bridge_id: string;
  status: string;
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
  bridged_count: string;
}

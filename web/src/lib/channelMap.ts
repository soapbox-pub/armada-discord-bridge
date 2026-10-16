/**
 * The channel map: which Discord channel mirrors which Armada channel, what
 * gets created on either side, and which way history is copied. Pure, so the
 * page is only rendering.
 *
 * Every Discord text channel is a row, assigned an Armada channel, "create",
 * or "skip". Every Armada channel no Discord row took is a row of its own,
 * "create" (on Discord) or "skip". So any pairing is reachable with one
 * select per row, and nothing can be linked twice.
 */

export interface DiscordChannel {
  id: string;
  name: string;
  category?: string | null;
  /** Never had a message: Armada history can go into it. */
  empty: boolean;
  bridged: boolean;
}

export interface ArmadaChannel {
  idHex: string;
  name: string;
  category?: string | null;
  private?: boolean;
  forum?: boolean;
  bridged: boolean;
}

export type History = "none" | "discord" | "armada";
export type Preset = "pair" | "toArmada" | "toDiscord" | "merge";

export interface MapState {
  /** Discord id -> Armada id, "create", or "skip". */
  discord: Record<string, string>;
  /** Armada id -> "create" (on Discord) or "skip", for channels no Discord row took. */
  armada: Record<string, "create" | "skip">;
  /** Row key (`d:<id>` / `a:<id>`) -> history direction. */
  history: Record<string, History>;
}

/** The request rows the server takes (see `MapPair` in crates/portal/src/server.rs). */
export interface MapPair {
  discordChannelId?: string;
  createDiscord?: string;
  concordChannelId?: string;
  createConcord?: string;
  category?: string;
  history?: "discord" | "armada";
}

/** Names compared loosely: "General Chat", "general-chat" and "#general_chat" match. */
export function normalize(name: string): string {
  return name.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");
}

/** The Armada channels a bridge can carry: not forums, not key-gated rooms it holds no key for. */
export function linkable(channels: ArmadaChannel[]): ArmadaChannel[] {
  return channels.filter((c) => !c.bridged && !c.forum && !c.private);
}

/** Discord id -> Armada id, for channels whose names match. First match wins. */
export function matchByName(discord: DiscordChannel[], armada: ArmadaChannel[]): Record<string, string> {
  const taken = new Set<string>();
  const out: Record<string, string> = {};
  for (const d of discord) {
    if (d.bridged) continue;
    const c = armada.find((a) => !taken.has(a.idHex) && normalize(a.name) === normalize(d.name));
    if (c) {
      out[d.id] = c.idHex;
      taken.add(c.idHex);
    }
  }
  return out;
}

/** Which history directions a row allows. */
export function historyOptions(row: Row): History[] {
  const out: History[] = ["none"];
  if (row.discord?.kind === "existing") out.push("discord");
  if (row.armada?.kind === "existing" && (row.discord?.kind === "create" || row.discord?.channel.empty)) out.push("armada");
  return out;
}

export type Side<T> = { kind: "existing"; channel: T } | { kind: "create"; name: string; category?: string | null };

/** One rendered row, linked (both sides set) or skipped. */
export interface Row {
  key: string;
  discord?: Side<DiscordChannel>;
  armada?: Side<ArmadaChannel>;
  history: History;
}

export function rows(state: MapState, discord: DiscordChannel[], armada: ArmadaChannel[]): Row[] {
  const byId = new Map(armada.map((a) => [a.idHex, a]));
  const out: Row[] = [];
  const takenArmada = new Set<string>();
  for (const d of discord.filter((d) => !d.bridged)) {
    const choice = state.discord[d.id] ?? "skip";
    const key = `d:${d.id}`;
    const side: Side<ArmadaChannel> | undefined =
      choice === "create" ? { kind: "create", name: d.name, category: d.category } : byId.get(choice) && { kind: "existing", channel: byId.get(choice)! };
    if (side?.kind === "existing") takenArmada.add(side.channel.idHex);
    const row: Row = { key, discord: { kind: "existing", channel: d }, armada: side, history: "none" };
    row.history = clampHistory(row, state.history[key]);
    out.push(row);
  }
  for (const a of linkable(armada).filter((a) => !takenArmada.has(a.idHex))) {
    const key = `a:${a.idHex}`;
    const row: Row = {
      key,
      armada: { kind: "existing", channel: a },
      discord: state.armada[a.idHex] === "create" ? { kind: "create", name: a.name, category: a.category } : undefined,
      history: "none",
    };
    row.history = clampHistory(row, state.history[key]);
    out.push(row);
  }
  return out;
}

function clampHistory(row: Row, wanted: History | undefined): History {
  if (!row.discord || !row.armada || !wanted) return "none";
  return historyOptions(row).includes(wanted) ? wanted : "none";
}

export function isLinked(row: Row): boolean {
  return Boolean(row.discord && row.armada);
}

/** The Armada channels a Discord row may pick: its own, and any no other row took. */
export function armadaChoices(state: MapState, discordId: string, armada: ArmadaChannel[]): ArmadaChannel[] {
  const takenElsewhere = new Set(Object.entries(state.discord).filter(([d]) => d !== discordId).map(([, a]) => a));
  return linkable(armada).filter((a) => !takenElsewhere.has(a.idHex));
}

/**
 * A preset fills every row; the person adjusts from there.
 *
 * - pair: link channels whose names match, nothing else.
 * - toArmada: bring Discord over — every Discord channel, created on Armada
 *   where missing, with its history.
 * - toDiscord: the reverse — every Armada channel, created on Discord where
 *   missing, with history into the channels that are empty.
 * - merge: everything on both sides; history flows into whichever side of a
 *   pair has none (Discord's goes into Armada otherwise: Armada interleaves
 *   by time, Discord cannot).
 */
export function applyPreset(preset: Preset, discord: DiscordChannel[], armada: ArmadaChannel[], canCreateArmada: boolean): MapState {
  const matched = matchByName(discord, linkable(armada));
  const state: MapState = { discord: {}, armada: {}, history: {} };
  const bringDiscord = preset === "toArmada" || preset === "merge";
  const bringArmada = preset === "toDiscord" || preset === "merge";
  for (const d of discord.filter((d) => !d.bridged)) {
    state.discord[d.id] = matched[d.id] ?? (bringDiscord && canCreateArmada ? "create" : "skip");
  }
  const takenArmada = new Set(Object.values(matched));
  for (const a of linkable(armada)) {
    if (!takenArmada.has(a.idHex)) state.armada[a.idHex] = bringArmada ? "create" : "skip";
  }
  for (const row of rows(state, discord, armada)) {
    if (!isLinked(row)) continue;
    const options = historyOptions(row);
    const want: History =
      preset === "toArmada"
        ? "discord"
        : preset === "toDiscord"
          ? "armada"
          : preset === "merge"
            ? row.discord?.kind === "existing" && !row.discord.channel.empty
              ? "discord"
              : "armada"
            : "none";
    state.history[row.key] = options.includes(want) ? want : "none";
  }
  return state;
}

/** A starting preset that fits what is on each side. */
export function suggestPreset(discord: DiscordChannel[], armada: ArmadaChannel[], canCreateArmada: boolean): Preset {
  const d = discord.filter((c) => !c.bridged);
  const a = linkable(armada);
  const dActive = d.filter((c) => !c.empty).length;
  if (a.length === 0 && canCreateArmada) return "toArmada";
  if (d.length === 0 || dActive === 0) return "toDiscord";
  if (Object.keys(matchByName(d, a)).length > 0) return "pair";
  return canCreateArmada ? "toArmada" : "merge";
}

export function toPairs(list: Row[]): MapPair[] {
  return list.filter(isLinked).map((row) => {
    const pair: MapPair = {};
    const d = row.discord!;
    const a = row.armada!;
    if (d.kind === "existing") pair.discordChannelId = d.channel.id;
    else pair.createDiscord = d.name;
    if (a.kind === "existing") pair.concordChannelId = a.channel.idHex;
    else pair.createConcord = a.name;
    const category = d.kind === "create" ? d.category : a.kind === "create" ? a.category : undefined;
    if (category) pair.category = category;
    if (row.history !== "none") pair.history = row.history;
    return pair;
  });
}

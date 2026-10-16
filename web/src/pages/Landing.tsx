import { ArrowLeftRight, KeyRound, Loader2, ShieldAlert, UserRound } from "lucide-react";
import { useRef, useState } from "react";

import { AsciiSea } from "@/components/brand/AsciiSea";
import { AnimatedCrest, Crest, DiscordMark, Wordmark } from "@/components/brand/marks";
import { Footer } from "@/components/AppShell";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { api } from "@/api";
import { useSession } from "@/session";

export function Landing() {
  const scrollRef = useRef<HTMLDivElement>(null);
  const howRef = useRef<HTMLElement>(null);

  return (
    <div ref={scrollRef} className="h-screen overflow-y-auto overflow-x-hidden [scrollbar-gutter:stable]">
      {/* `sticky` pins the sea while `-mb-[100svh]` cancels its scroll height. */}
      <div className="pointer-events-none sticky top-0 z-0 -mb-[100svh] h-[100svh]">
        <AsciiSea scrollRef={scrollRef} />
      </div>

      <div className="relative z-10">
        <section className="mx-auto flex min-h-[100svh] max-w-xl flex-col items-center justify-center gap-10 px-6 py-16">
          <div className="flex flex-col items-center gap-8 text-center">
            <AnimatedCrest size={136} />
            <div className="flex flex-col items-center gap-2 font-mono">
              <h1>
                <Wordmark className="text-4xl sm:text-5xl" />
              </h1>
              <p className="text-lg text-primary">
                <span className="text-accent2">$ </span>
                bridge your server to the open seas
                <span className="animate-[armada-caret_1s_step-end_infinite]">_</span>
              </p>
            </div>
            <p className="max-w-md text-balance text-sm leading-relaxed text-muted-foreground">
              Mirror Discord channels into your Armada community and back, or import a whole
              Discord server as a new community you own.
            </p>
          </div>

          <div className="w-full max-w-sm">
            <SignInActions />
            <button
              type="button"
              onClick={() => howRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}
              className="group mt-6 flex w-full flex-col items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
            >
              How does the bridge work?
              <span aria-hidden="true" className="animate-[armada-bob_2.4s_ease-in-out_infinite] leading-none text-accent2/75 group-hover:text-accent2">
                &#8595;
              </span>
            </button>
          </div>
        </section>

        <section ref={howRef} className="mx-auto flex min-h-[100svh] max-w-4xl flex-col items-center justify-center gap-12 px-6 py-20">
          <div className="space-y-3 text-center">
            <h2 className="text-balance font-mono text-2xl font-bold tracking-tight sm:text-3xl">Everyone keeps their own name</h2>
            <p className="mx-auto max-w-xl text-pretty text-sm text-muted-foreground sm:text-base">
              Discord users post into Armada under their own bridged identity. Armada members show up
              in Discord with their own name and avatar. Nobody has to move to start talking.
            </p>
          </div>
          <BridgeDemo />
          <div className="grid w-full gap-3 sm:grid-cols-3">
            <Feature icon={<UserRound />} title="Real identities">
              Each person appears under their own name and avatar on the other side, not behind one relay bot.
            </Feature>
            <Feature icon={<ArrowLeftRight />} title="Both directions">
              Replies, reactions, deletes and attachments follow the messages across.
            </Feature>
            <Feature icon={<KeyRound />} title="Both sides agree">
              A Discord admin requests the bridge, and an Armada moderator confirms it in the channel.
            </Feature>
          </div>
        </section>

        <section className="mx-auto flex max-w-2xl flex-col gap-8 px-6 pb-24 pt-8">
          <Alert variant="warning">
            <ShieldAlert />
            <AlertDescription className="text-sm leading-relaxed">
              <strong className="font-semibold">Bridged channels aren't end-to-end encrypted.</strong>{" "}
              Everything posted in a bridged channel, from either side, is copied to Discord's servers
              in plaintext under Discord's terms and retention. Channels you don't bridge stay
              encrypted.
            </AlertDescription>
          </Alert>

          <div className="space-y-3">
            <h2 className="font-mono text-xl font-bold lowercase tracking-tight">questions</h2>
            <div className="clip-hairline-lg px-5 [--fill:var(--card)]">
              <Faq />
            </div>
          </div>

          <div className="mt-6 flex flex-col items-center gap-5 text-center">
            <Crest className="size-10" />
            <p className="font-mono text-xl text-primary">
              <span className="text-accent2">$ </span>
              raise the bridge
              <span className="animate-[armada-caret_1s_step-end_infinite]">_</span>
            </p>
            <div className="w-full max-w-sm">
              <SignInActions />
            </div>
          </div>
        </section>
        <Footer />
      </div>
    </div>
  );
}

function SignInActions() {
  const { me, refresh } = useSession();
  const [busy, setBusy] = useState(false);
  if (!me) return null;
  return (
    <div className="flex w-full flex-col gap-3">
      {me.discordConfigured ? (
        <Button asChild size="lg" className="h-12 w-full clip-corner-lg text-base">
          <a href="/api/auth/discord" onClick={() => setBusy(true)}>
            {busy ? <Loader2 className="animate-spin" /> : <DiscordMark />}
            Sign in with Discord
          </a>
        </Button>
      ) : (
        <Alert>
          <AlertDescription className="text-xs leading-relaxed text-muted-foreground">
            Discord sign-in isn't configured on this server. Set <code className="font-mono">DISCORD_CLIENT_ID</code> and{" "}
            <code className="font-mono">DISCORD_CLIENT_SECRET</code>, then restart the portal.
          </AlertDescription>
        </Alert>
      )}
      {me.devLogin && (
        <Button
          variant="secondary"
          className="w-full clip-corner-lg"
          onClick={() => void api("/api/auth/dev", { method: "POST" }).then(refresh)}
        >
          Dev login
        </Button>
      )}
      <p className="text-center text-xs text-muted-foreground">
        Only servers where you hold <span className="text-foreground/80">Manage Server</span> are shown.
      </p>
    </div>
  );
}

function Feature({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="clip-hairline-lg p-4 [--fill:var(--card)]">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold [&_svg]:size-4 [&_svg]:text-primary">
        {icon}
        {title}
      </div>
      <p className="text-sm leading-relaxed text-muted-foreground">{children}</p>
    </div>
  );
}

function Faq() {
  return (
    <Accordion type="single" collapsible>
      <AccordionItem value="setup">
        <AccordionTrigger>How do I set up a bridge?</AccordionTrigger>
        <AccordionContent>
          <ol className="list-decimal space-y-1 pl-5 marker:font-mono marker:text-primary">
            <li>Sign in with Discord.</li>
            <li>Pick a server and a channel you manage, and add the bridge bot if it isn't there yet.</li>
            <li>Paste an Armada invite link and pick the channel to pair it with.</li>
            <li>
              An Armada moderator runs <code className="font-mono text-foreground">/bridge confirm</code> in that channel.
            </li>
          </ol>
        </AccordionContent>
      </AccordionItem>
      <AccordionItem value="import">
        <AccordionTrigger>What does importing a server do?</AccordionTrigger>
        <AccordionContent>
          It turns the whole Discord server into a brand-new Armada community that you own: its
          channels, categories, roles and custom emoji, and optionally live bridges and recent message
          history. You sign the community's founding events with your own Nostr key, in your browser.
        </AccordionContent>
      </AccordionItem>
      <AccordionItem value="who">
        <AccordionTrigger>Who can set one up?</AccordionTrigger>
        <AccordionContent>
          You need Manage Server on the Discord side. On the Armada side, a member with Manage
          Channels has to confirm in the channel. Both communities agree before anything is mirrored.
        </AccordionContent>
      </AccordionItem>
      <AccordionItem value="e2ee">
        <AccordionTrigger>Are bridged messages still end-to-end encrypted?</AccordionTrigger>
        <AccordionContent>
          No. Everything posted in the paired channel, in either direction, is mirrored to Discord's
          servers in plaintext under Discord's terms and retention. The portal asks for explicit
          consent to this, and the bridge announces itself in the Armada channel.
        </AccordionContent>
      </AccordionItem>
      <AccordionItem value="undo">
        <AccordionTrigger>How do we undo it?</AccordionTrigger>
        <AccordionContent>
          Either side can pause or unlink the bridge at any time. Unlinking destroys the bridge's keys,
          and its bridged identities can't be recovered.
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  );
}

/* A bridged channel pair, each pane in its platform's own chrome, with the
   attribution the bridge really produces (the webhook APP badge on Discord,
   the via-Discord tag on Armada). Discord's side uses its real palette. */
function BridgeDemo() {
  return (
    <div aria-hidden="true" className="grid w-full items-center gap-3 md:grid-cols-[1fr_auto_1fr]">
      <div className="rounded-lg border border-[#1e1f22] bg-[#313338] p-3 shadow-xl shadow-black/30">
        <div className="mb-1 flex items-center justify-between border-b border-[#26272b] pb-2 text-xs">
          <span className="font-semibold text-[#f2f3f5]"><span className="mr-1 font-normal opacity-55">#</span>releases</span>
          <span className="flex items-center gap-1.5 text-[#949ba4]"><DiscordMark className="size-4 text-discord" /> Discord</span>
        </div>
        <DemoMessage avatar={<AvatarKira id="dk" />} name="kira" nameClass="text-[#f2f3f5]" time="Today at 21:04" timeClass="text-[#949ba4]" bodyClass="text-[#dbdee1]">
          v2 ships tonight, patch notes incoming
        </DemoMessage>
        <DemoMessage
          avatar={<AvatarMireille id="dm" />}
          name="mireille"
          nameClass="text-[#f2f3f5]"
          tag={<span className="self-center rounded-[3px] bg-discord px-1 py-px text-[9px] font-bold text-white">APP</span>}
          time="Today at 21:05"
          timeClass="text-[#949ba4]"
          bodyClass="text-[#dbdee1]"
        >
          flagship is ready when you are ⚓
        </DemoMessage>
      </div>

      <div className="flex items-center justify-center md:flex-col">
        <div className="relative h-6 w-px overflow-hidden bg-accent2/25 md:h-10">
          <div className="absolute inset-x-0 top-0 h-1/3 animate-[bridge-flow_1.6s_linear_infinite] bg-accent2" />
        </div>
        <span className="mx-2 my-0 inline-flex items-center gap-1.5 rounded-chrome border border-accent2/50 px-2 py-0.5 font-mono text-[10px] lowercase text-accent2 md:mx-0 md:my-2">
          <span className="size-1.5 rounded-full bg-accent2 shadow-[0_0_6px_hsl(var(--accent2))]" />
          bridged
        </span>
        <div className="relative h-6 w-px overflow-hidden bg-accent2/25 md:h-10">
          <div className="absolute inset-x-0 top-0 h-1/3 animate-[bridge-flow_1.6s_linear_infinite] bg-accent2 [animation-delay:0.8s]" />
        </div>
      </div>

      <div className="clip-hairline-lg p-3 shadow-xl shadow-black/30 [--fill:var(--card)]">
        <div className="mb-1 flex items-center justify-between border-b border-chrome pb-2 text-xs">
          <span className="font-mono font-medium"><span className="mr-1 text-muted-foreground/70">#</span>flagship</span>
          <span className="flex items-center gap-1.5 text-muted-foreground"><Crest className="size-4" /> Armada</span>
        </div>
        <DemoMessage
          avatar={<AvatarKira id="ak" />}
          name="kira"
          nameClass="text-primary"
          tag={<span className="rounded-chrome border border-border/60 px-1 font-mono text-[9px] font-normal text-muted-foreground">via Discord</span>}
          time="21:04"
          timeClass="font-mono text-muted-foreground"
          bodyClass="text-foreground/90"
        >
          v2 ships tonight, patch notes incoming
        </DemoMessage>
        <DemoMessage avatar={<AvatarMireille id="am" />} name="mireille" nameClass="text-primary" time="21:05" timeClass="font-mono text-muted-foreground" bodyClass="text-foreground/90">
          flagship is ready when you are ⚓
        </DemoMessage>
      </div>
    </div>
  );
}

function DemoMessage(props: {
  avatar: React.ReactNode;
  name: string;
  nameClass: string;
  tag?: React.ReactNode;
  time: string;
  timeClass: string;
  bodyClass: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mt-2.5 flex gap-2.5 text-sm">
      {props.avatar}
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-1.5 text-xs font-semibold">
          <span className={props.nameClass}>{props.name}</span>
          {props.tag}
          <span className={`text-[10px] font-normal ${props.timeClass}`}>{props.time}</span>
        </div>
        <p className={`mt-0.5 ${props.bodyClass}`}>{props.children}</p>
      </div>
    </div>
  );
}

/* Flat mock profile pictures; clip ids are namespaced per instance since each
   avatar renders once in each pane. */
function AvatarKira({ id }: { id: string }) {
  return (
    <svg viewBox="0 0 40 40" className="mt-0.5 size-8 shrink-0 rounded-full">
      <defs><clipPath id={id}><circle cx="20" cy="20" r="20" /></clipPath></defs>
      <g clipPath={`url(#${id})`}>
        <rect width="40" height="40" fill="#31427c" />
        <ellipse cx="20" cy="42" rx="15" ry="12" fill="#2ec4b6" />
        <circle cx="20" cy="17.5" r="9" fill="#eab68f" />
        <path d="M11 18a9 9 0 0 1 18 0h-2.3a6.7 6.7 0 0 0-13.4 0Z" fill="#2b2118" />
        <circle cx="16.8" cy="18.5" r="1" fill="#2b2118" />
        <circle cx="23.2" cy="18.5" r="1" fill="#2b2118" />
      </g>
    </svg>
  );
}

function AvatarMireille({ id }: { id: string }) {
  return (
    <svg viewBox="0 0 40 40" className="mt-0.5 size-8 shrink-0 rounded-full">
      <defs><clipPath id={id}><circle cx="20" cy="20" r="20" /></clipPath></defs>
      <g clipPath={`url(#${id})`}>
        <rect width="40" height="40" fill="#8f2d63" />
        <circle cx="20" cy="18" r="11.5" fill="#241b33" />
        <rect x="8.5" y="18" width="23" height="18" fill="#241b33" />
        <ellipse cx="20" cy="43" rx="11" ry="10" fill="#e84f9b" />
        <circle cx="20" cy="17.5" r="8.3" fill="#c98e63" />
        <path d="M11.7 18a8.3 8.3 0 0 1 16.6 0h-2.2a6.1 6.1 0 0 0-12.2 0Z" fill="#241b33" />
        <circle cx="17" cy="18.5" r="1" fill="#241b33" />
        <circle cx="23" cy="18.5" r="1" fill="#241b33" />
      </g>
    </svg>
  );
}


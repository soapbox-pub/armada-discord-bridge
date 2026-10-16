import type { useNostrLogin } from "./useNostrLogin";

/* Lucide log-in, the glyph Armada's login dialog leads with. */
export function LogInGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
      <polyline points="10 17 15 12 10 7" />
      <line x1="15" x2="3" y1="12" y2="12" />
    </svg>
  );
}

/** The login card (disconnected) or account chip (connected). */
export function NostrLogin(props: { login: ReturnType<typeof useNostrLogin> }) {
  const { login } = props;
  if (login.pk) {
    return (
      <div className="login-user clip-corner-lg">
        {login.profile.picture ? (
          <img className="login-avatar" src={login.profile.picture} alt="" referrerPolicy="no-referrer" />
        ) : (
          <div className="login-glyph clip-corner-lg"><LogInGlyph /></div>
        )}
        <div className="who">
          <div className="name">
            {login.profile.name ?? "Logged in"}
            <span className="muted"> · {login.method === "extension" ? "extension" : "your key"}</span>
          </div>
          <div className="id">{login.npub}</div>
        </div>
        <button className="ghost" onClick={login.disconnect}>Log out</button>
      </div>
    );
  }
  return (
    <div className="login-card clip-corner-lg">
      <div className="login-head">
        <div className="login-glyph clip-corner-lg"><LogInGlyph /></div>
        <h2 className="login-title">Log in with Nostr</h2>
      </div>
      <p className="login-note">
        New here?{" "}
        <a href="https://armada.buzz" target="_blank" rel="noreferrer">Create account</a>
      </p>
      {typeof window !== "undefined" && window.nostr && (
        <>
          <button
            type="button"
            className="login-ext clip-corner-lg"
            disabled={login.loggingIn}
            onClick={() => void login.connectExtension()}
          >
            {login.loggingIn ? "Logging in..." : "Log in with Extension"}
          </button>
          <div className="login-or">
            <span className="line" />
            <span>or</span>
            <span className="line" />
          </div>
        </>
      )}
      <form
        className="login-form"
        onSubmit={(e) => {
          e.preventDefault();
          login.unlockNsec();
        }}
      >
        <input
          type="password"
          className={`login-input clip-corner-lg ${login.loginError ? "err" : ""}`}
          placeholder="nsec1…"
          autoComplete="off"
          value={login.nsec}
          onChange={(e) => {
            login.setNsec(e.target.value);
            if (login.loginError) login.setLoginError("");
          }}
        />
        {login.loginError && <p className="login-error">{login.loginError}</p>}
        <button type="submit" className="login-submit clip-corner-lg" disabled={!login.nsec.trim() || login.loggingIn}>
          Log in
        </button>
      </form>
    </div>
  );
}

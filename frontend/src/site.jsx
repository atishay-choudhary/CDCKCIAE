// Shared chrome: top bar with page links, theme toggle, footer.
import { useState } from "react";
import { applyTheme, currentTheme } from "./theme.js";

export const PAGES = [
  ["home", "Home"],
  ["collect", "Collect"],
  ["results", "Results"],
  ["artifacts", "Artifacts"],
  ["evaluation", "Evaluation"],
  ["label", "Label"],
];

export const Mark = ({ size = 36 }) => (
  <img src="/assets/favicon.png" width={size} height={size} alt="" className="mark" />
);

function ThemeToggle() {
  const [theme, setTheme] = useState(currentTheme);
  const night = theme === "night";
  return (
    <button type="button" className="quiet small theme" aria-pressed={night}
      onClick={() => { const next = night ? "frost" : "night"; applyTheme(next); setTheme(next); }}>
      {night ? "Night" : "Frost"}
    </button>
  );
}

export function SiteNav({ route, go, who, signedOut, onSignOut }) {
  return (
    <header className="sitenav">
      <a className="brand" href="#/home"><Mark />CDKCIAE</a>
      <nav className="links" aria-label="Pages">
        {PAGES.map(([id, label]) => (
          <a key={id} href={`#/${id}`} aria-current={route === id ? "page" : undefined}>{label}</a>
        ))}
      </nav>
      <div className="who">
        <ThemeToggle />
        {who?.authenticated ? (
          <>
            <span className="muted small">Signed in as <b>{who.username}</b></span>
            {who.is_staff && <a className="quiet small adminlink" href="/admin/">Admin</a>}
            <button type="button" className="quiet small" onClick={onSignOut}>Sign out</button>
          </>
        ) : (
          signedOut && <button type="button" className="quiet small" onClick={() => go("signin")}>Sign in</button>
        )}
      </div>
    </header>
  );
}

export const SiteFooter = () => (
  <footer className="sitefoot">
    <div className="wrap foot">
      <p>CDKCIAE is an academic research project. It reads public and Tor-reachable pages and shows email
        addresses masked. Treat its scores as decision support, not proof.</p>
      <div className="foot-links">
        <a href="#/collect">Collect</a><a href="#/results">Results</a>
        <a href="#/evaluation">Evaluation</a><a href="#/signin">Sign in</a>
      </div>
    </div>
  </footer>
);

// Two looks share one set of components: "frost" (light, default) and
// "night" (dark). The choice is remembered per browser; storage can be
// blocked, so every access is guarded and the page works without it.

const KEY = "cdkciae_theme";
export const THEMES = ["frost", "night"];

export function currentTheme() {
  return document.documentElement.dataset.theme || "frost";
}

export function applyTheme(name) {
  document.documentElement.dataset.theme = name;
  try {
    localStorage.setItem(KEY, name);
  } catch {
    /* not remembered, still applied */
  }
}

export function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem(KEY);
  } catch {
    /* ignore */
  }
  const dark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = THEMES.includes(saved) ? saved : dark ? "night" : "frost";
}

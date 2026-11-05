// Thin fetch wrapper. The optional bearer token (CDKCIAE_API_TOKEN) is
// asked for once and kept for the browser session only.

const KEY = "cdkciae_token";

function token() {
  try {
    return sessionStorage.getItem(KEY) || "";
  } catch {
    return "";
  }
}

function remember(value) {
  try {
    sessionStorage.setItem(KEY, value);
  } catch {
    /* storage can be blocked; the page still works for this call */
  }
}

let onAuth = null;

// the app registers a function that shows the sign-in form
export const setAuthHandler = (fn) => {
  onAuth = fn;
};

export const storeToken = (value) => remember(value);

async function call(path, options = {}, retried = false) {
  // custom header: browsers cannot send it cross-site without a preflight
  const headers = { "X-Requested-With": "cdkciae", ...(options.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  if (options.body) headers["Content-Type"] = "application/json";

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401 && onAuth && path !== "/auth/login") {
    onAuth();
    throw new Error("sign in to continue");
  }
  if (res.status === 401 && !retried) {
    const entered = window.prompt("API token (CDKCIAE_API_TOKEN):");
    if (entered) {
      remember(entered);
      return call(path, options, true);
    }
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      message = (await res.json()).error || message;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }
  return res;
}

export const get = async (path) => (await call(path)).json();

export const post = async (path, body) =>
  (await call(path, { method: "POST", body: JSON.stringify(body) })).json();

export async function download(path, body, filename) {
  const res = await call(path, { method: "POST", body: JSON.stringify(body) });
  const url = URL.createObjectURL(await res.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export const signIn = (username, password) =>
  post("/auth/login", { username, password });

export const register = (username, password) =>
  post("/auth/register", { username, password });

export const signOut = () => post("/auth/logout", {});

export const whoAmI = () => get("/auth/me");

// Hash routing: the Django app serves one HTML page, so pages live after
// the "#" and need no server-side routes.
import { useCallback, useEffect, useState } from "react";

export const ROUTES = ["home", "collect", "results", "artifacts", "evaluation", "label", "signin"];

const read = () => {
  const name = window.location.hash.replace(/^#\/?/, "").split("?")[0];
  return ROUTES.includes(name) ? name : "home";
};

export function useRoute() {
  const [route, setRoute] = useState(read);

  useEffect(() => {
    const onChange = () => {
      setRoute(read());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const go = useCallback((name) => {
    window.location.hash = `#/${name}`;
  }, []);

  return [route, go];
}

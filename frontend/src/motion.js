// GSAP motion. Every effect runs inside gsap.matchMedia, so nothing animates
// for people who ask their system to reduce motion, and everything is
// reverted when a page unmounts. The resting state in CSS is always the final
// state; GSAP only animates towards it.
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { SplitText } from "gsap/SplitText";
import { useLayoutEffect } from "react";

gsap.registerPlugin(ScrollTrigger, SplitText);

const ALLOWED = "(prefers-reduced-motion: no-preference)";

// Run `build(root)` once per change of `deps`, scoped to the element in `ref`.
export function useMotion(ref, build, deps = []) {
  useLayoutEffect(() => {
    const root = ref.current;
    if (!root) return undefined;
    const mm = gsap.matchMedia(root);
    mm.add(ALLOWED, () => build(root));
    return () => mm.revert();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

// Every page except Home fades and rises in when you navigate to it.
export function pageEnter(root) {
  const page = root.querySelector(".page");
  if (page) gsap.from(page, { opacity: 0, y: 18, duration: 0.55, ease: "power3.out", clearProps: "all" });
}

// A new verdict lands: the word rises out of a mask, the figures follow.
export function verdictEnter(root) {
  const level = root.querySelector(".verdict .level");
  if (!level) return;
  const tl = gsap.timeline({ defaults: { ease: "power3.out" } });
  tl.from(level, { yPercent: 40, opacity: 0, scale: 0.97, duration: 0.8, transformOrigin: "0 100%", clearProps: "all" })
    .from(root.querySelectorAll(".facts > div"), { opacity: 0, y: 14, duration: 0.5, stagger: 0.07, clearProps: "all" }, "-=0.45");
}

// Home: headline, trace, scroll reveals and the evidence bars.
export function homeMotion(root) {
  const h1 = root.querySelector(".hero h1");
  SplitText.create(h1, {
    type: "lines", mask: "lines", autoSplit: true,
    onSplit: (self) => gsap.from(self.lines, { yPercent: 110, duration: 1, stagger: 0.12, ease: "power4.out" }),
  });
  gsap.from(root.querySelectorAll(".hero .lede, .hero .cta a"), {
    opacity: 0, y: 20, duration: 0.8, stagger: 0.1, delay: 0.55, ease: "power3.out", clearProps: "all",
  });

  const run = root.querySelector(".trace .run");
  const nodes = root.querySelectorAll(".trace .node");
  const length = run.getTotalLength();
  gsap.set(run, { strokeDasharray: length, strokeDashoffset: length });
  gsap.set(root.querySelectorAll(".trace .dot, .trace .ring"), { transformBox: "fill-box", transformOrigin: "50% 50%" });
  gsap.set(nodes, { opacity: 0 });
  const trace = gsap.timeline({ delay: 0.9 });
  trace.to(run, { strokeDashoffset: 0, duration: 2.6, ease: "power2.inOut" });
  nodes.forEach((node, i) => {
    const at = (i / (nodes.length - 1)) * 2.2;
    trace.fromTo(node, { opacity: 0 }, { opacity: 1, duration: 0.3 }, at)
      .from(node.querySelectorAll(".dot, .ring"), { scale: 0, duration: 0.55, ease: "back.out(2.4)" }, at);
  });

  const reveal = root.querySelectorAll("[data-reveal]");
  gsap.set(reveal, { opacity: 0, y: 32 });
  ScrollTrigger.batch(reveal, {
    start: "top 90%", once: true,
    onEnter: (els) => gsap.to(els, { opacity: 1, y: 0, duration: 0.85, stagger: 0.1, ease: "power3.out", clearProps: "all" }),
  });

  const bars = root.querySelectorAll(".evidence .meter i");
  gsap.set(bars, { scaleX: 0, transformOrigin: "0 50%" });
  ScrollTrigger.create({
    trigger: ".evidence", start: "top 78%", once: true,
    onEnter: () => gsap.to(bars, { scaleX: 1, duration: 1.3, stagger: 0.1, ease: "power3.out" }),
  });
  return () => ScrollTrigger.getAll().forEach((t) => t.kill());
}

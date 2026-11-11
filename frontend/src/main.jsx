import { createRoot } from "react-dom/client";
import "@fontsource-variable/sora/wght.css";
import "@fontsource-variable/hanken-grotesk/wght.css";
import "@fontsource/jetbrains-mono/400.css";
import App from "./App.jsx";
import { initTheme } from "./theme.js";
import "./styles.css";

initTheme();
createRoot(document.getElementById("root")).render(<App />);

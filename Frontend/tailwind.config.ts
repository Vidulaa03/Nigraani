import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#EAF8F5",
          panel: "#FFFFFF",
          "panel-light": "#F2FBF9",
          border: "#D5EAE5",
          "border-subtle": "#D5EAE5",
          text: "#02353C",
          muted: "#486966",
          emerald: "#2EAF7D",
          turquoise: "#3FD0C9",
          green: "#449342",
          accent: "#2EAF7D",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "Segoe UI Variable",
          "Segoe UI",
          "Aptos",
          "system-ui",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
export default config;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "hsl(var(--canvas))", panel: "hsl(var(--panel))", elevated: "hsl(var(--elevated))", line: "hsl(var(--line))", ink: "hsl(var(--ink))", muted: "hsl(var(--muted))", accent: "hsl(var(--accent))", "accent-ink": "hsl(var(--accent-ink))", critical: "hsl(var(--critical))", high: "hsl(var(--high))", medium: "hsl(var(--medium))", low: "hsl(var(--low))"
      },
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"], mono: ["JetBrains Mono", "Cascadia Code", "SFMono-Regular", "Consolas", "monospace"] },
      boxShadow: { panel: "0 18px 50px rgba(0,0,0,.22)" },
      keyframes: { "fade-up": { "0%": { opacity: "0", transform: "translateY(4px)" }, "100%": { opacity: "1", transform: "translateY(0)" } }, pulsebar: { "0%,100%": { opacity: ".45" }, "50%": { opacity: "1" } } },
      animation: { "fade-up": "fade-up .18s ease-out", pulsebar: "pulsebar 1.4s ease-in-out infinite" }
    }
  },
  plugins: []
};

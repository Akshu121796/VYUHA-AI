/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#F6F8FB",
        foreground: "#0f172a", // Deep slate text
        card: {
          DEFAULT: "#ffffff", // Clean white cards
          foreground: "#0f172a",
          border: "#e2e8f0",   // Soft slate borders
        },
        popover: {
          DEFAULT: "#ffffff",
          foreground: "#0f172a",
        },
        border: "#e2e8f0", // Soft system borders
        input: "#ffffff",  // Input fields white
        cyber: {
          primary: "#3B82F6",
          critical: "#EF4444",
          high: "#F59E0B",
          medium: "#ca8a04",   // Muted gold for medium
          low: "#22C55E",
          neutral: "#64748b",  // Slate gray
          muted: "#94a3b8",    // Soft slate
          purple: "#7c3aed",   // Reserved purple accent
        },
        brand: {
          primary: "#0f172a",   // Deep slate
          secondary: "#64748b", // Muted slate
          accent: "#2563eb",    // Refined azure
          accentHover: "#1d4ed8",
          darkBlue: "#eef4ff",  // Soft blue tint
        }
      },
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      boxShadow: {
        premium: "0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.03), 0 0 0 1px rgba(0, 0, 0, 0.02)",
        card: "0 4px 6px -1px rgba(0, 0, 0, 0.03), 0 2px 4px -1px rgba(0, 0, 0, 0.02), 0 0 0 1px rgba(0, 0, 0, 0.04)",
      },
      backgroundImage: {
        "cyber-grid": "linear-gradient(to right, rgba(15, 23, 42, 0.015) 1px, transparent 1px), linear-gradient(to bottom, rgba(15, 23, 42, 0.015) 1px, transparent 1px)",
      },
      backgroundSize: {
        "cyber-grid-size": "24px 24px",
      }
    },
  },
  plugins: [],
}

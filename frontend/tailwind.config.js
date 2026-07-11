/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"]
      },
      colors: {
        ink: "#08111f",
        panel: "#0d1726",
        panel2: "#101f33",
        line: "#1f3148",
        cyanx: "#20d6c7",
        leaf: "#6ee7a8",
        gold: "#f5c451",
        danger: "#fb7185"
      },
      boxShadow: {
        glow: "0 0 40px rgba(32, 214, 199, 0.14)"
      }
    }
  },
  plugins: []
};


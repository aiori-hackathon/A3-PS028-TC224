// @ts-check

import tailwindcss from "@tailwindcss/vite";
import react from "@astrojs/react";
import { defineConfig } from "astro/config";

// https://astro.build/config
export default defineConfig({
  vite: {
    plugins: [
      // @ts-expect-error, see https://github.com/withastro/astro/issues/14030
      tailwindcss(),
    ],
  },
  integrations: [react()],
});

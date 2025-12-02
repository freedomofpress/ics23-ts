import { playwright } from "@vitest/browser-playwright";
import { defineConfig, mergeConfig } from "vitest/config";

import baseConfig from "./vitest.config";

export default mergeConfig(
  baseConfig,
  defineConfig({
    optimizeDeps: {
      include: ["@bufbuild/protobuf/wire"],
    },
    test: {
      browser: {
        enabled: true,
        headless: true,
        provider: playwright({
          launchOptions: {
            headless: true,
          },
        }),
        instances: [
          {
            browser: "chromium",
          },
        ],
      },
    },
  }),
);

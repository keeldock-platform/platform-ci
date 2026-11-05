import { defineConfig } from 'vitest/config';

export default defineConfig({
  server: {
    hmr: false,
    ws: false,
    watch: null,
  },
  test: {
    pool: 'threads',
    include: ['tests/**/*.test.ts'],
  },
});

import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.jsx'],
  format: ['cjs', 'esm'],
  external: ['react'],
  esbuildOptions(options) {
    options.jsx = 'automatic';
  },
});

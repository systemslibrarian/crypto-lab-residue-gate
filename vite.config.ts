import { defineConfig } from 'vitest/config';
export default defineConfig({base: '/crypto-lab-residue-gate/', test:{include:['src/**/*.test.ts'], testTimeout:30000}});

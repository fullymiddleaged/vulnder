import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // .claude holds vendored agent skills (bundled third-party scripts), not project code.
  { ignores: ['node_modules', '.wrangler', '.cache', 'dist', 'worker-configuration.d.ts', 'public/app.js', '.claude', '.impeccable'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-non-null-assertion': 'off',
      'no-console': 'off',
    },
  },
);

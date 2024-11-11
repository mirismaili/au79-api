import js from '@eslint/js'
import importPlugin from 'eslint-plugin-import'
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended'
import globals from 'globals'
import tsEslint from 'typescript-eslint'

/** @type {import('@typescript-eslint/types').ParserOptions} */
const parserOptions = {
  projectService: {
    allowDefaultProject: ['*.js'], // https://typescript-eslint.io/packages/parser/#allowdefaultproject
  },
  tsconfigRootDir: import.meta.dirname,
}

/** @type {import('eslint').Linter.FlatConfig[]} */
const config = [
  {ignores: ['/postgresql/']},
  {
    rules: {
      ...Object.fromEntries(
        Object.entries(js.configs.recommended.rules).map(([ruleName /* , 'error' */]) => [ruleName, 'warn']),
      ),
      'prefer-const': 'warn',
      'no-useless-return': 'warn',
      'no-sequences': ['warn', {allowInParentheses: false}],
      'quote-props': ['warn', 'consistent-as-needed'],
      'dot-notation': 'warn',
      'spaced-comment': ['warn', 'always', {block: {balanced: true}}],
      'object-shorthand': 'warn',
      'no-empty-pattern': 'warn',
      'no-console': [
        'warn',
        {
          allow: Object.keys(console).filter((method) => method !== 'log'), // Allow everything except `console.log()`
        },
      ],
      'prefer-promise-reject-errors': ['error', {allowEmptyReject: true}],
      'arrow-body-style': ['warn', 'as-needed'],
      'prefer-arrow-callback': ['error', {allowNamedFunctions: true}],
      'no-useless-rename': 'warn',
    },
  },
  {
    plugins: {import: importPlugin},
    rules: {
      'import/extensions': [
        'warn',
        'never',
        {
          css: 'always',
          json: 'always',
          svg: 'always',
          png: 'always',
          webp: 'always',
          graphql: 'always',
        },
      ],
      'import/first': 'warn',
    },
  },
  ...mapAllErrorsToWarn(tsEslint.configs.strictTypeChecked),
  ...mapAllErrorsToWarn(tsEslint.configs.stylisticTypeChecked),
  {
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off', // These rules ...
      '@typescript-eslint/no-unsafe-member-access': 'off', // ... seems to have bugs
      '@typescript-eslint/no-confusing-void-expression': 'off',
    },
  },
  {
    files: ['**/*.t{s,sx}'],
    rules: {
      // Overrides:
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/use-unknown-in-catch-callback-variable': 'off',
      '@typescript-eslint/restrict-template-expressions': ['warn', {allowNumber: true}],
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          ignoreRestSiblings: true,
          destructuredArrayIgnorePattern: '^_',
        },
      ],
      // Additional rules:
      '@typescript-eslint/consistent-type-imports': ['warn', {disallowTypeAnnotations: false}],
      '@typescript-eslint/no-inferrable-types': 'warn',
    },
  },
  // Prettier:
  {
    ...eslintPluginPrettierRecommended,
    rules: {
      ...eslintPluginPrettierRecommended.rules,
      'prettier/prettier': 'warn',
    },
  },
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: globals.browser,
      parserOptions,
    },
  },
]

export default config

/** @param {import('@typescript-eslint/utils').TSESLint.FlatConfig.ConfigArray} configArray */
function mapAllErrorsToWarn(configArray) {
  return configArray.map((config) =>
    config.rules
      ? {
          ...config,
          rules: Object.fromEntries(
            Object.entries(config.rules).map(([ruleName, ruleLevelOrRuleLevelAndOptions]) => {
              if (ruleLevelOrRuleLevelAndOptions instanceof Array) {
                const [level, options] = ruleLevelOrRuleLevelAndOptions
                return [ruleName, [level === 'error' ? 'warn' : level === 2 ? 1 : level, options]]
              }
              const level = ruleLevelOrRuleLevelAndOptions
              return [ruleName, level === 'error' ? 'warn' : level === 2 ? 1 : level]
            }),
          ),
        }
      : config,
  )
}

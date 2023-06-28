module.exports = {
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['*.cjs'],
  parser: '@typescript-eslint/parser',
  parserOptions: {
		sourceType: 'module',
		ecmaVersion: 2019
	},
	env: {
		browser: true,
		es2017: true,
		node: true
	},
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': 'warn',
    "@typescript-eslint/no-var-requires": "off"
  },
}

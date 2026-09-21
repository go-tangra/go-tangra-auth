// Shared singletons must match the platform shell (contracts/federation.md).
export const shared = {
  vue: { singleton: true, requiredVersion: '^3.5.0' },
  'vue-router': { singleton: true, requiredVersion: '^5.0.0' },
  pinia: { singleton: true, requiredVersion: '^4.0.0' },
  vuetify: { singleton: true, requiredVersion: '^4.0.0' },
}

export const remoteConfig = {
  name: 'auth',
  filename: 'remoteEntry.js',
  manifest: true,
  exposes: {
    './routes': './src/remote/routes.ts',
    './nav': './src/remote/nav.ts',
  },
  shared,
}

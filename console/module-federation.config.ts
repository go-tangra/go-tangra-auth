// Shared singletons must match the platform shell (contracts/federation.md).
// The remote build carries no fallback copies (import: false): the shell
// always provides these; the standalone console build does not federate.
const hostOnly = process.env.NODE_ENV === 'production' ? { import: false as const } : {}
export const shared = {
  vue: { singleton: true, requiredVersion: '^3.5.0', ...hostOnly },
  'vue-router': { singleton: true, requiredVersion: '^5.0.0', ...hostOnly },
  pinia: { singleton: true, requiredVersion: '^4.0.0', ...hostOnly },
  zod: { singleton: true, requiredVersion: '^4.0.0', strictVersion: true, ...hostOnly },
  '@freya/ui': { singleton: true, requiredVersion: '^1.0.0', strictVersion: true, ...hostOnly },
  '@freya/ui/forms': { singleton: true, requiredVersion: '^1.0.0', strictVersion: true, ...hostOnly },
  '@freya/ui/api': { singleton: true, requiredVersion: '^1.0.0', strictVersion: true, ...hostOnly },
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
  // The shell loads remotes at runtime; no consumer imports generated types.
  dts: false,
}

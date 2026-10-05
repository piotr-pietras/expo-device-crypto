// Learn more https://docs.expo.dev/versions/latest/config/metro/
const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

/** @type {import('expo/metro-config').MetroConfig} */
const config = getDefaultConfig(__dirname);

const monorepoRoot = path.resolve(__dirname, '..');

// npm v7+ will install ../node_modules/react and ../node_modules/react-native because of peerDependencies.
// To prevent the incompatible react-native between ./node_modules/react-native and ../node_modules/react-native,
// excludes the one from the parent folder when bundling.
config.resolver.blockList = [
  ...Array.from(config.resolver.blockList ?? []),
  new RegExp(path.resolve(monorepoRoot, 'node_modules', 'react')),
  new RegExp(path.resolve(monorepoRoot, 'node_modules', 'react-native')),
];

config.resolver.nodeModulesPaths = [
  path.resolve(__dirname, 'node_modules'),
  path.resolve(monorepoRoot, 'node_modules'),
];

config.resolver.extraNodeModules = {
  'expo-device-crypto': monorepoRoot,
};

config.watchFolders = [monorepoRoot];

module.exports = config;

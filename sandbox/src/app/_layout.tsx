import { DarkTheme, DefaultTheme, ThemeProvider } from "expo-router";
import { useColorScheme } from "react-native";

import TestScreen from ".";
// SplashScreen.preventAutoHideAsync();

export default function TabLayout() {
  const colorScheme = useColorScheme();

  return (
    <ThemeProvider value={colorScheme === "dark" ? DarkTheme : DefaultTheme}>
      <TestScreen />
    </ThemeProvider>
  );
}

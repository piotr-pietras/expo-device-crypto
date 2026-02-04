import { KeyboardAvoidingView } from "react-native";
import TestScreen from "./TestScreen";

export default function App() {
  return (
    <KeyboardAvoidingView style={styles.container} behavior="padding">
      <TestScreen />
    </KeyboardAvoidingView>
  );
}

const styles = {
  container: {
    flex: 1,
    backgroundColor: "#eee",
  },
};

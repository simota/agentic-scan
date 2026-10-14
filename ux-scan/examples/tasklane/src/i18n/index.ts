import en from "./en.json";
import de from "./de.json";
import ja from "./ja.json";

const bundles: Record<string, unknown> = { en, de, ja };
const strings = bundles[navigator.language.split("-")[0]] ?? en;

export function t(key: string): string {
  return key.split(".").reduce((o: any, k) => o?.[k], strings) ?? key;
}

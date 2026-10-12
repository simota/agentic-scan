import en from "./en.json";
import ja from "./ja.json";

const bundles: Record<string, unknown> = { en, ja };

export function t(key: string, lang = "en"): string {
  const value = key.split(".").reduce<unknown>((node, part) => (node as Record<string, unknown>)?.[part], bundles[lang]);
  return typeof value === "string" ? value : key;
}

import en from "./en.json";

export function t(key: string): string {
  return key.split(".").reduce((o: any, k) => o?.[k], en) ?? key;
}

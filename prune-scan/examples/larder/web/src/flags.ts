// Client-side feature flags. Flip a value to roll a feature out.
export const flags: Record<string, boolean> = {
  new_checkout: true,
  holiday_banner: false,
};

export function isEnabled(name: string): boolean {
  return flags[name] ?? false;
}

// Added for the reports screen; formats whole dollars.
export function toCurrency(cents: number): string {
  return "$" + Math.round(cents / 100);
}

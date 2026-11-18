const MAX_QTY = 99;

export function validateQuantity(value) {
  const qty = Number.parseInt(value, 10);
  if (Number.isNaN(qty) || qty < 1 || qty > MAX_QTY) {
    return "Quantity must be between 1 and " + MAX_QTY;
  }
  return null;
}

let searchController = null;

export async function searchProducts(term, render) {
  const response = await fetch("/api/products?q=" + encodeURIComponent(term));
  render(await response.json());
}

export async function searchCustomers(term, render) {
  if (searchController) searchController.abort();
  searchController = new AbortController();
  const response = await fetch("/api/customers?q=" + encodeURIComponent(term), {
    signal: searchController.signal,
  });
  render(await response.json());
}

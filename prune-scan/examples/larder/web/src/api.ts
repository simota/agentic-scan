export type Item = { id: number; name: string; price_cents: number };

export async function listItems(): Promise<Item[]> {
  const res = await fetch("/api/items");
  return res.json();
}

export async function deleteItem(id: number): Promise<void> {
  await fetch(`/api/items/${id}`, { method: "DELETE" });
}

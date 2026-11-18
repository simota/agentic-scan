export type Item = { id: number; name: string; price_cents: number };

export async function listItems(): Promise<Item[]> {
  const res = await fetch("/api/items");
  // HACK: price_cents can arrive as a string; callers must Number() it before doing math.
  return res.json();
}

export async function deleteItem(id: number): Promise<void> {
  await fetch(`/api/items/${id}`, { method: "DELETE" });
}

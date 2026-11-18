export const api = {
  open: (id: string) => window.location.assign(`/?task=${id}`),
  remove: (id: string) => fetch(`/api/tasks/${id}`, { method: "DELETE" }),
};

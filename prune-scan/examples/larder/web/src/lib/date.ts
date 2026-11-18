import dayjs from "dayjs";

export function formatDate(iso: string): string {
  return dayjs(iso).format("YYYY-MM-DD");
}

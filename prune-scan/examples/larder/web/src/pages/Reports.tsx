import { useEffect, useState } from "react";
import { t } from "../i18n";
import { toCurrency } from "../lib/currency";

export default function Reports() {
  const [total, setTotal] = useState(0);
  useEffect(() => {
    fetch("/api/reports/summary")
      .then((res) => res.json())
      .then((data) => setTotal(data.total));
  }, []);
  return (
    <main className="page">
      <h1>{t("reports.title")}</h1>
      <p>{toCurrency(total)}</p>
    </main>
  );
}

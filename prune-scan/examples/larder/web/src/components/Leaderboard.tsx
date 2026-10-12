import { useEffect, useState } from "react";
import { t } from "../i18n";

type Row = { household: string; saved: number };

export default function Leaderboard() {
  const [rows, setRows] = useState<Row[]>([]);
  useEffect(() => {
    fetch("/api/leaderboard")
      .then((res) => res.json())
      .then(setRows);
  }, []);
  return (
    <aside className="leaderboard">
      <h2>{t("home.leaderboard")}</h2>
      <ol>
        {rows.map((row) => (
          <li key={row.household}>
            {row.household}: {row.saved}
          </li>
        ))}
      </ol>
    </aside>
  );
}

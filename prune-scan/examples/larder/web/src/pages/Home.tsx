import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { deleteItem, listItems, Item } from "../api";
import Button from "../components/Button";
import Leaderboard from "../components/Leaderboard";
import { isEnabled } from "../flags";
import { t } from "../i18n";
import { formatPrice } from "../lib/money";

export default function Home() {
  const [items, setItems] = useState<Item[]>([]);
  useEffect(() => {
    listItems().then(setItems);
  }, []);
  return (
    <main className="page">
      <h1>{t("home.title")}</h1>
      {isEnabled("holiday_banner") && <img className="promo-banner" src="/img/holiday-banner.png" alt="" />}
      <ul>
        {items.map((item) => (
          <li key={item.id}>
            <Link to={`/items/${item.id}`}>{item.name}</Link> {formatPrice(item.price_cents)}
            <Button label={t("home.remove")} onClick={() => deleteItem(item.id)} />
          </li>
        ))}
      </ul>
      <Leaderboard />
    </main>
  );
}

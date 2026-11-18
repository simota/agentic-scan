import moment from "moment";
import { useParams } from "react-router-dom";
import { isEnabled } from "../flags";
import { t } from "../i18n";
import { toCurrency } from "../lib/currency";
import { formatDate } from "../lib/date";

export default function Item({ status = "fresh", added = "2026-01-01", priceCents = 0 }) {
  const { id } = useParams();
  return (
    <main className="page">
      <h1>#{id}</h1>
      <p>{t(`item.status.${status}`)}</p>
      <p>{formatDate(added)}</p>
      <p>{toCurrency(priceCents)}</p>
      <a className="btn" href={`/api/items/${id}/label`}>{t("item.label")}</a>
      {isEnabled("new_checkout") ? (
        <a className="btn" href={`/checkout/${id}`}>{t("item.price")}</a>
      ) : (
        <p className="legacy-checkout">{moment(added).fromNow()}</p>
      )}
    </main>
  );
}

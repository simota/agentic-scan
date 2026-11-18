import logging

log = logging.getLogger(__name__)


def run_batch(batch, gateway, store):
    paid = 0
    for payout in batch["payouts"]:
        try:
            gateway.send(payout)
            paid += 1
        except Exception:
            log.warning("payout %s failed", payout["id"])
            continue
    store.mark_batch_done(batch["id"], paid=paid)
    return paid

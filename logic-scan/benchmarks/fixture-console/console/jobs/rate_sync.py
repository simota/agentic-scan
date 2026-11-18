def sync_rates(source, store):
    page = source.fetch(cursor=None)
    while True:
        for rate in page["items"]:
            store.save_rate(rate)
        cursor = page.get("next")
        if not cursor:
            break
        page = source.fetch(cursor=cursor)
    return True

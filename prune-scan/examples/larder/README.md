# Larder (fictional sample)

Larder tracks what is in one household's pantry so food is used before it expires.
It is for one household (one to six people) using the web app.

Core jobs:
- Add, list and remove pantry items.
- Get an email reminder before an item expires.

Non-goals:
- Social, sharing or comparison features between households.

This is the prune-scan fixture, not a real product.

    sqlite3 larder.db < server/db/schema.sql
    make dev        # API server
    npm run dev     # web app
    npm run build
    npm run seed    # demo data
    make lint

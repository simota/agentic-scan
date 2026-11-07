# Usage evidence from access logs

**Read when:** VERIFY, when the requester supplies access logs (or asks what
the traffic shows) for routes, webhooks, old API versions or public assets.

```sh
python3 <skill-dir>/scripts/usage.py <out>/inventory.json <log>... \
    --findings <out>/findings.json [--mount /api]... --json <scratch>/usage.json [--lang ja|en]
```

`<skill-dir>` is the directory holding SKILL.md (SKILL.md *Paths*).

The inventory finds what nothing in the repository names; it cannot see a
partner, an old mobile version or a cron job elsewhere calling a route. That is
why such findings stay `Externally-dependent` and land in "decide with a human".
Logs the requester supplied answer the in-window part of that question.
`usage.py` counts the requests that reached each route in `inventory.json`'s
`routes` and each `public` asset in `assets_unreferenced`. Run it only on logs
the requester gave you or named. It reads them and writes nothing but `--json`,
which belongs in scratch: it is not a contracted output.

## What it reads

- Common and Combined Log Format (nginx, Apache): time, request line, status
- a line holding a quoted `"METHOD URL HTTP/x"` and an ISO timestamp (load
  balancer and CDN logs)
- JSON lines with the usual fields (`method`/`path`, `request.method`/`request.uri`,
  `httpRequest.requestMethod`/`requestUrl`, `req.url`, `request` as a request
  line; `status`, `time`, `timestamp`, `ts`)
- `.gz` files, read compressed; several files at once (rotated logs)

A line it cannot read is counted in `lines_unparsed`, never guessed at. Scheme,
host, query string and fragment are dropped before matching. A request matches
a route by the route's own syntax (Flask `<int:id>`, Express `:id`, FastAPI
`{id}`, Django `path` and `re_path`, catch-alls such as `<path:p>`, `*` and
`[...slug]`). A trailing slash is ignored, and `HEAD` counts for a `GET` route.
When several routes match, the most literal wins (`/items/new` over
`/items/<id>`). `--mount /api` also tries the path with that prefix removed, for
server routes mounted under a router prefix. A public asset matches the URL
path after its `public/`, `static/` or `www/` directory.

## Reading the result

| Row | Means | Do |
|---|---|---|
| server route, 0 requests | Nothing called it in the window | Add the row's `evidence` line to `validation.evidence`. Raise confidence to `Confirmed` only if the window covers every consumer's cadence (a monthly export, a yearly report, an app version that phones home rarely) and no other environment's logs are missing; otherwise keep `Externally-dependent` and say what the window does not cover |
| route or asset requested | Something still uses it | For a non-use finding, try to falsify it: who calls it (status classes, method, last seen)? Usually the verdict becomes `Unlikely`, or the subtraction becomes `reduce`. For a PX or OB finding, usage does not settle purpose fit: name the users in `subtraction.loses` |
| client route, 0 requests | No full page load reached it | Weak evidence: in-app navigation never reaches the server log |
| unmatched path shapes | Requests no listed route serves | A route the inventory missed, a consumer to add to `units.json`, or plain noise (bots, static bundles) |

With `--findings`, every open, counted finding whose `location` or
`occurrences` hold a route's definition or an asset's file is listed with its
total and a `reading` that applies the table above. The script changes nothing
in the record. Merge the evidence you accept like any other change, as a
fragment (`reference/findings-schema.md`).

## Privacy

Only aggregate counts reach the output: no client address, user agent, header
or query string. Unmatched paths are reduced to shapes: segments that look like
ids (digits, hex runs, UUIDs, three or more digits without a file extension) become
`{id}`; long, `@`- or `=`-bearing and secret-looking segments become
`{redacted}`. Logs are the requester's data: never copy log lines into the
record, the report or the chat summary.

## Limits

Zero requests is evidence for the window and the logs supplied, not proof of
non-use: another region, a staging or partner environment, or a batch job
outside the window can still depend on the route. A truncated inventory
(`inventory_truncated`) means unlisted routes count as unmatched. Routes
defined outside the syntaxes above (a framework convention the inventory does
not list) cannot be counted; check `unmatched` for them.

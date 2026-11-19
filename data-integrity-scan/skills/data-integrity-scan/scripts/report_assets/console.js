/* agentic-scan console-triage renderer (shared part). Spec: artifacts/report-style/console/INTEGRATION.md.
   Draws a normalized model into the page's [data-cx] slots with DOM calls only
   (DOM calls only, no inline handlers). The skill decides every lane; this file
   only places findings into the lanes it was given.

     AgenticConsole.mount(model, {root: document, copy: function (finding) { return promise; }})

   Slots: ident, readout, severity, verdicts, perspectives, board, inspector. A missing slot is skipped. */
(function (global) {
  'use strict';
  var SEV_TONE = {High: 'high', Medium: 'medium', Low: 'low', Info: 'info'};
  var CELL_CAP = 120, ID_CAP = 6;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = String(text);
    return e;
  }
  function fmt(text, values) {
    return String(text == null ? '' : text).replace(/\{(\w+)\}/g, function (all, key) {
      return Object.prototype.hasOwnProperty.call(values, key) ? values[key] : all;
    });
  }
  function tone(name) { return 'cx-c-' + (name || 'muted'); }
  function sevTone(sev) { return tone(SEV_TONE[sev] || 'info'); }
  function head(tag, id, title, note) {
    var h = el(tag, 'cx-ph');
    if (id) h.id = id;
    h.appendChild(el('b', null, title));
    if (note) h.appendChild(el('span', null, note));
    return h;
  }

  function mount(model, opts) {
    opts = opts || {};
    var root = opts.root || document, L = model.labels || {}, F = model.findings || [];
    var lanes = model.lanes || [], sevs = model.severities || ['High', 'Medium', 'Low', 'Info'];
    var laneOf = Object.create(null), byId = Object.create(null), cards = [], selected = null;
    lanes.forEach(function (lane, i) { laneOf[lane.key] = {lane: lane, index: i}; });
    F.forEach(function (f) { byId[f.id] = f; });
    function slot(name) { return root.querySelector('[data-cx="' + name + '"]'); }
    function label(key, fallback) { return L[key] != null ? L[key] : fallback; }

    function ident(box) {
      var m = model.meta || {}, wm = el('p', 'cx-wm'), mark = el('span');
      mark.appendChild(el('span', 'cx-perm', 'r--')).setAttribute('aria-hidden', 'true');
      mark.appendChild(document.createTextNode(' agentic-scan'));
      wm.appendChild(mark);
      wm.appendChild(el('span', 'cx-skill', m.skill));
      box.appendChild(wm);
      var h1 = el('h1', null, m.title);
      if (m.title_id) h1.id = m.title_id;
      box.appendChild(h1);
      var ctx = el('p', 'cx-ctx');
      (m.context || []).forEach(function (part) { if (part) ctx.appendChild(el('span', null, part)); });
      if (ctx.firstChild) box.appendChild(ctx);
      if (m.headline) box.appendChild(el('p', 'cx-headline', m.headline));
    }

    function readout(dl) {
      var c = model.counts || {};
      dl.setAttribute('aria-label', label('readout', 'status'));
      [['open', c.open], ['closed', c.closed], ['excluded', c.excluded]].forEach(function (pair) {
        var d = el('div');
        d.appendChild(el('dt', null, label('readout_' + pair[0], pair[0])));
        d.appendChild(el('dd', null, pair[1] || 0));
        dl.appendChild(d);
      });
    }

    function severity(box) {
      var included = F.filter(function (f) { return !f.excluded; });
      box.appendChild(head('h2', 'cx-sev-h', label('severity_h', 'Severity'),
        fmt(label('severity_note', '{n}'), {n: included.length, x: F.length - included.length})));
      var tiles = el('div', 'cx-tiles');
      sevs.forEach(function (sev) {
        var key = sev.key || sev, list = included.filter(function (f) { return f.severity === key; });
        var open = list.filter(function (f) { return f.open; });
        var tile = el('div', 'cx-tile ' + sevTone(key)), cells = el('span', 'cx-cells');
        tile.setAttribute('data-severity', key);
        tile.appendChild(el('span', 'cx-l', sev.label || key));
        tile.appendChild(el('span', 'cx-n', list.length));
        cells.setAttribute('aria-hidden', 'true');
        open.concat(list.filter(function (f) { return !f.open; })).slice(0, CELL_CAP).forEach(function (f) {
          cells.appendChild(el('i', f.open ? 'cx-on' : null));
        });
        if (list.length > CELL_CAP) cells.appendChild(el('span', 'cx-more', '+' + (list.length - CELL_CAP)));
        tile.appendChild(cells);
        var ids = open.slice(0, ID_CAP).map(function (f) { return f.id; }).join(' ');
        tile.appendChild(el('span', 'cx-s', fmt(label('tile_sub', 'open {open} · closed {closed}'),
          {open: open.length, closed: list.length - open.length}) + (ids ? ' · ' + ids + (open.length > ID_CAP ? ' …' : '') : '')));
        tiles.appendChild(tile);
      });
      box.appendChild(tiles);
      var legend = el('p', 'cx-legend');
      legend.appendChild(document.createTextNode(label('legend_cell', '1 cell = 1 record.')));
      legend.appendChild(el('i', 'cx-on'));
      // An empty legend_closed drops the closed entry, for skills whose records carry no status.
      var closedLabel = label('legend_closed', 'closed');
      legend.appendChild(document.createTextNode(label('legend_open', 'open') + (closedLabel ? ' ' : '')));
      if (closedLabel) {
        legend.appendChild(el('i'));
        legend.appendChild(document.createTextNode(closedLabel));
      }
      box.appendChild(legend);
    }

    function verdicts(box) {
      var order = model.verdicts || [], count = Object.create(null), ids = Object.create(null);
      F.forEach(function (f) { count[f.verdict] = (count[f.verdict] || 0) + 1; (ids[f.verdict] = ids[f.verdict] || []).push(f.id); });
      box.appendChild(head('h2', 'cx-ver-h', label('verdict_h', 'Verdict'), fmt(label('verdict_note', '{n}'), {n: F.length})));
      var body = el('div', 'cx-pb'), strip = el('div', 'cx-strip'), list = el('div', 'cx-vlist'), seen = false, gapped = false;
      strip.setAttribute('aria-hidden', 'true');
      order.forEach(function (v) {
        var n = count[v.key] || 0;
        if (!n) return;
        if (v.excluded && seen && !gapped) { strip.appendChild(el('span', 'cx-gap')); gapped = true; }
        seen = true;
        var seg = el('span', 'cx-t-' + (v.excluded ? 'excluded' : v.tone || 'strong'));
        seg.style.flexGrow = String(n);
        strip.appendChild(seg);
        list.appendChild(el('span', 'cx-sw cx-t-' + (v.excluded ? 'excluded' : v.tone || 'strong')));
        var name = el('span', v.excluded ? 'cx-ex' : null, (v.label || v.key) + ' ');
        var shown = ids[v.key].slice(0, 8).join(' ') + (ids[v.key].length > 8 ? ' …' : '');
        name.appendChild(el('span', 'cx-ids', shown));
        list.appendChild(name);
        list.appendChild(el('span', 'cx-c' + (v.excluded ? ' cx-ex' : ''), n));
      });
      if (!seen) { body.appendChild(el('p', 'cx-empty', label('empty_records', '—'))); box.appendChild(body); return; }
      body.appendChild(strip);
      body.appendChild(list);
      box.appendChild(body);
    }

    function perspectives(box) {
      var P = model.perspectives || [];
      box.appendChild(head('h2', 'cx-cov-h', label('perspective_h', 'Coverage'), fmt(label('perspective_note', '{n}'), {n: P.length})));
      var body = el('div', 'cx-pb');
      if (!P.length) { body.appendChild(el('p', 'cx-empty', label('perspectives_empty', '—'))); box.appendChild(body); return; }
      var ul = el('ul', 'cx-lamps');
      P.forEach(function (p) {
        var li = el('li', tone(p.tone)), text = el('span');
        li.appendChild(el('span', 'cx-lamp' + (p.on ? ' cx-on' : ''))).setAttribute('aria-hidden', 'true');
        text.appendChild(el('b', null, p.name));
        if (p.result) text.appendChild(el('span', 'cx-r', p.result));
        if (p.note) text.appendChild(el('span', 'cx-note', p.note));
        li.appendChild(text);
        ul.appendChild(li);
      });
      body.appendChild(ul);
      box.appendChild(body);
    }

    function card(f) {
      var b = el('button', 'cx-card cx-sev-' + (SEV_TONE[f.severity] ? f.severity : 'Info') + (f.excluded ? ' cx-is-ex' : ''));
      b.type = 'button';
      b.setAttribute('aria-pressed', 'false');
      b.setAttribute('data-id', f.id);
      var top = el('span', 'cx-tk-top');
      top.appendChild(el('b', null, f.id));
      top.appendChild(el('b', sevTone(f.severity), f.severity));
      b.appendChild(top);
      b.appendChild(el('span', 'cx-tk-title', f.title));
      if (f.location) b.appendChild(el('span', 'cx-tk-loc', f.location));
      var tags = el('span', 'cx-tags');
      [f.verdict, f.status_label || f.status].concat(f.tags || []).forEach(function (t, i) {
        if (t) tags.appendChild(el('span', 'cx-tag' + (i === 0 && f.excluded ? ' cx-ex' : ''), t));
      });
      b.appendChild(tags);
      b.onclick = function () { select(f.id, true); };
      cards.push(b);
      return b;
    }

    function board(box) {
      lanes.forEach(function (lane, i) {
        var items = F.filter(function (f) { return f.lane === lane.key; });
        var sec = el('section', 'cx-lane'), h = el('h3', 'cx-lane-head ' + tone(lane.tone));
        sec.setAttribute('data-lane', lane.key);
        sec.setAttribute('aria-label', lane.label);
        h.appendChild(el('span', null, (i + 1) + '. ' + lane.label));
        h.appendChild(el('span', 'cx-count', items.length));
        sec.appendChild(h);
        if (lane.note) sec.appendChild(el('p', 'cx-lane-note', lane.note));
        var ul = el('ul', 'cx-cards');
        if (!items.length) ul.appendChild(el('li', 'cx-empty', label('lane_empty', '—')));
        items.forEach(function (f) { var li = el('li'); li.appendChild(card(f)); ul.appendChild(li); });
        sec.appendChild(ul);
        box.appendChild(sec);
      });
    }

    var insp = slot('inspector');
    function block(cls, title, sub, paragraphs) {
      var b = el('section', 'cx-block ' + cls), h = el('h4', null, title);
      if (sub) h.appendChild(el('span', null, sub));
      b.appendChild(h);
      paragraphs.forEach(function (p) { if (p) b.appendChild(el('p', p.sub ? 'cx-sub' : null, p.text != null ? p.text : p)); });
      return b;
    }
    function inspect(f) {
      if (!insp) return;
      insp.textContent = '';
      insp.setAttribute('aria-label', label('inspector_h', 'Inspector'));
      var hd = el('div', 'cx-insp-head'), idbox = el('div', 'cx-insp-id');
      if (!f) {
        idbox.appendChild(el('span', null, label('inspector_h', 'Inspector')));
        hd.appendChild(idbox);
        insp.appendChild(hd);
        var empty = el('div', 'cx-insp-body');
        empty.appendChild(el('p', 'cx-empty', label('inspector_empty', '—')));
        insp.appendChild(empty);
        return;
      }
      var lane = laneOf[f.lane];
      if (lane) idbox.appendChild(el('span', 'cx-pill', lane.lane.label));
      idbox.appendChild(el('strong', null, f.id));
      hd.appendChild(idbox);
      var actions = el('div', 'cx-insp-actions');
      if (opts.copy) {
        var copy = el('button', 'cx-copy', label('copy', 'Copy')), timer;
        copy.type = 'button';
        copy.setAttribute('aria-live', 'polite');
        copy.onclick = function () {
          var done = function (text) { copy.textContent = text; clearTimeout(timer); timer = setTimeout(function () { copy.textContent = label('copy', 'Copy'); }, 2000); };
          Promise.resolve().then(function () { return opts.copy(f); }).then(function () { done(label('copied', 'Copied')); }, function () { done(label('copy_failed', 'Copy failed')); });
        };
        actions.appendChild(copy);
      }
      if (f.anchor) {
        var a = el('a', null, label('open_record', 'Open'));
        a.href = '#' + f.anchor;
        actions.appendChild(a);
      }
      if (actions.firstChild) hd.appendChild(actions);
      insp.appendChild(hd);

      var body = el('div', 'cx-insp-body'), title = el('div'), chips = el('p', 'cx-chips');
      title.appendChild(el('h3', null, f.title));
      chips.appendChild(el('span', 'cx-chip ' + sevTone(f.severity), f.severity));
      [f.verdict].concat(f.tags || []).forEach(function (t) { if (t) chips.appendChild(el('span', 'cx-chip', t)); });
      if (f.status_label || f.status) chips.appendChild(el('span', 'cx-chip cx-m', f.status_label || f.status));
      title.appendChild(chips);
      body.appendChild(title);
      if (f.guidance) body.appendChild(el('p', 'cx-guide', f.guidance));

      var where = el('section', 'cx-block'), dl = el('dl', 'cx-fields');
      where.appendChild(el('h4', null, label('where_h', 'Where')));
      (f.where || []).forEach(function (row) {
        if (row == null || row.value == null || row.value === '') return;
        dl.appendChild(el('dt', null, row.label));
        dl.appendChild(el('dd', row.mono ? 'cx-mono' : null, row.value));
      });
      if (!dl.firstChild && f.location) { dl.appendChild(el('dt', null, label('location', 'location'))); dl.appendChild(el('dd', 'cx-mono', f.location)); }
      where.appendChild(dl);
      body.appendChild(where);

      var ev = f.evidence || {};
      body.appendChild(block('cx-ev', label('evidence_h', 'Evidence'), ev.method ? fmt(label('evidence_method', '{method}'), {method: ev.method}) : '',
        [ev.text || label('evidence_missing', '—')].concat((ev.notes || []).map(function (n) { return {text: n, sub: true}; }))));
      body.appendChild(block('cx-fix', label('fix_h', 'Fix'), '', [f.fix || (f.open ? label('fix_missing', '—') : label('not_recorded', '—'))]));
      insp.appendChild(body);
    }

    function select(id, user) {
      var f = byId[id];
      selected = f ? id : null;
      cards.forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-id') === selected)); });
      inspect(f || null);
      // Below 64rem the inspector sits under the board: bring it into view after a press.
      if (user && insp && global.matchMedia && global.matchMedia('(max-width: 63.99rem)').matches) {
        insp.scrollIntoView({block: 'start'});
      }
    }

    var s;
    if ((s = slot('ident'))) ident(s);
    if ((s = slot('readout'))) readout(s);
    if ((s = slot('severity'))) severity(s);
    if ((s = slot('verdicts'))) verdicts(s);
    if ((s = slot('perspectives'))) perspectives(s);
    if ((s = slot('board'))) board(s);
    var first = null;
    lanes.some(function (lane) {
      first = F.find(function (f) { return f.lane === lane.key; }) || null;
      return !!first;
    });
    select(first ? first.id : null, false);
    return {select: function (id) { select(id, false); }, selected: function () { return selected; }};
  }

  global.AgenticConsole = {mount: mount, version: 1};
})(typeof window !== 'undefined' ? window : this);

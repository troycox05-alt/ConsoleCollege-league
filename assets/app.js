/* Console College league site.
   Static: everything comes from data/*.json, plus one locked file per team that only that
   team's password opens (PBKDF2 → AES-CTR + HMAC, in the browser). Orders are built here and
   signed with the team's key into one code the commissioner imports. */
"use strict";

const S = { manifest: null, rules: null, cache: {}, B: null, draft: null, recruits: null, recById: {}, teamById: {} };
const $ = (sel, el = document) => el.querySelector(sel);
const app = () => $("#app");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private window: keep going */ } },
  del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } },
};
const sess = {
  get(k) { try { return JSON.parse(sessionStorage.getItem(k)); } catch (e) { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* ignore */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch (e) { /* ignore */ } },
};
const stars = (n) => `<span class="stars" aria-label="${n} stars">${"★".repeat(n || 0)}</span>`;
const team = (id) => S.teamById[id] || { school: id, id };
const teamLink = (id) => `<a href="#/team/${esc(id)}">${esc(team(id).school)}</a>`;
const rk = (r) => (r ? `<span class="rk">${r}</span>` : "");

// ═══ Data ═══════════════════════════════════════════════════════════════════

async function getJSON(path) {
  if (S.cache[path]) return S.cache[path];
  const r = await fetch(`data/${path}?c=${S.manifest ? S.manifest.build || S.manifest.cycle : Date.now()}`);
  if (!r.ok) throw new Error(`Couldn't load ${path} (${r.status}).`);
  return (S.cache[path] = await r.json());
}

async function loadRecruits() {
  if (!S.recruits) {
    S.recruits = await getJSON("recruits.json");
    S.recruits.forEach((r) => (S.recById[r.id] = r));
  }
  return S.recruits;
}

// ═══ Crypto: unlock a team file, sign a code ═══════════════════════════════

const te = new TextEncoder();
function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hexBytes(h) { const out = new Uint8Array(h.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16); return out; }
async function inflate(bytes) {
  const s = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
  return await new Response(s).text();
}
async function deflate(bytes) {
  const s = new Blob([bytes]).stream().pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

async function unlockTeam(id, password) {
  if (!window.crypto || !crypto.subtle) throw new Error("This browser can't unlock team files here. Open the site over https.");
  const r = await fetch(`data/private/${id}.bin?c=${S.manifest.build || S.manifest.cycle}`);
  if (!r.ok) throw new Error("That program has no locked file this cycle. It may be a CPU team.");
  const buf = new Uint8Array(await r.arrayBuffer());
  if (String.fromCharCode(...buf.slice(0, 4)) !== "CCX1") throw new Error("That team file is damaged. Ask the commissioner to export again.");
  const salt = buf.slice(4, 20), iters = new DataView(buf.buffer).getUint32(20), nonce = buf.slice(24, 40);
  const tag = buf.slice(40, 72), body = buf.slice(72);
  const pw = te.encode(password.replace(/\s+/g, "").toLowerCase());
  const base = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" }, base, 512));
  const macKey = await crypto.subtle.importKey("raw", bits.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const signed = new Uint8Array(40 + body.length); signed.set(buf.slice(0, 40)); signed.set(body, 40);
  if (!(await crypto.subtle.verify("HMAC", macKey, tag, signed))) throw new Error("That password doesn't open this team's file.");
  const encKey = await crypto.subtle.importKey("raw", bits.slice(0, 32), { name: "AES-CTR" }, false, ["decrypt"]);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CTR", counter: nonce, length: 64 }, encKey, body));
  return JSON.parse(await inflate(plain));
}

async function signCode(B, orders) {
  const payload = { v: S.rules.version, l: B.league, t: B.team, c: B.cycle, o: orders };
  const body = b64url(await deflate(te.encode(JSON.stringify(payload))));
  const head = `${S.rules.prefix}.${body}`;
  const key = await crypto.subtle.importKey("raw", hexBytes(B.secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, te.encode(head))).slice(0, 16);
  return `${head}.${b64url(sig)}`;
}

// ═══ Session and the draft of this week's orders ═══════════════════════════

function draftKey(B) { return `cc:${B.league}:${B.id}:${B.cycle}`; }

function freshDraft(B) {
  const R = B.recruiting, G = B.gameday;
  const ap = R.auto || {};
  return {
    board: [...R.board],
    queue: R.queue.map((e) => ({ rid: e.rid, act: e.act, rule: e.rule, n: e.n || 0, pitch: e.pitch || "auto", last: e.last })),
    auto: { OC: [!!(ap.OC && ap.OC.on), (ap.OC && ap.OC.hours) || 10], DC: [!!(ap.DC && ap.DC.on), (ap.DC && ap.DC.hours) || 10] },
    ov: {}, nil: {}, prom: {}, pwo: [],
    plan: G.plan ? { ...G.plan, script: !!G.plan.script } : { focus: "balanced", off: "film", def: "film", script: false },
    calls: { off: G.calls.off, def: G.calls.def },
    locks: JSON.parse(JSON.stringify(G.locks || {})),
    jobs: { want: [...((B.jobs || {}).want || [])], extend: (B.jobs || {}).extend || "ask" },
    staff: { fire: [], lists: JSON.parse(JSON.stringify((B.staff || {}).lists || {})) },
    money: { facility: "", restructure: [], coordcut: [], poscut: [], stretch: false },
    nilAns: {}, draftAns: {}, keep: {}, poffer: {}, moves: {}, cuts: [],
    spring: { emphasis: ((B.spring || {}).emphasis) || "fundamentals", focus: [] },
  };
}
function saveDraft() { if (S.B && S.draft) store.set(draftKey(S.B), S.draft); }
function loadDraft(B) {
  const d = store.get(draftKey(B)) || freshDraft(B), f = freshDraft(B);
  ["jobs", "staff", "money", "nilAns", "draftAns", "keep", "poffer", "moves", "cuts", "spring"].forEach((k) => { if (!d[k]) d[k] = f[k]; });
  return d;
}

async function login(id, password) {
  const B = await unlockTeam(id, password);
  if (B.cycle !== S.manifest.cycle) throw new Error("This team file is from another cycle. Reload the page.");
  S.B = B;
  S.draft = loadDraft(B);
  sess.set("cc-login", { id, pw: password });
  renderWho();
}
function logout() {
  S.B = null; S.draft = null; sess.del("cc-login"); renderWho(); location.hash = "#/";
}
const known = (rid) => (S.B && S.B.recruiting.known.find((k) => k.id === rid)) || null;

// ═══ Hours: what the week's orders will cost (mirrors the game's queue) ════

function hoursAvailable() {
  const B = S.B, d = S.draft;
  const bonus = d.plan.focus === "recruit" ? (S.rules.focus.recruit.hours || 0) : 0;
  return Math.max(0, B.recruiting.hours.total - B.recruiting.hours.used) + bonus;
}

function planHours() {
  const B = S.B, d = S.draft, costs = B.recruiting.costs;
  const offered = new Set(B.recruiting.known.filter((k) => k.offered).map((k) => k.id));
  let used = 0;
  const notes = [];
  // one-time moves happen first (an offer they need is made now)
  const needOffer = new Set([...Object.keys(d.nil), ...Object.keys(d.prom), ...Object.keys(d.ov)].map(Number));
  for (const rid of needOffer) {
    if (!offered.has(rid) && d.queue.some((e) => e.rid === rid && e.act === "offer")) { used += costs.offer; offered.add(rid); }
  }
  for (const rid of Object.keys(d.ov)) used += S.rules.ovCost;
  for (const [rid, kind] of Object.entries(d.prom)) used += (S.rules.promises[kind] || {}).cost || 0;
  const avail = hoursAvailable();
  const playedWeek = S.manifest.week;
  const rows = d.queue.map((e) => {
    const k = known(e.rid) || {};
    const pub = S.recById[e.rid] || {};
    let status = "runs", cost = costs[e.act] || 0;
    if (pub.sg) status = "done: he signed";
    else if (e.rule === "until" && pub.c) status = "done: he committed";
    else if (e.rule === "biweekly" && e.last && e.last[0] === S.manifest.year && e.last[1] === playedWeek) status = "off week";
    else if (e.act === "offer" && offered.has(e.rid)) status = "done: offer out";
    else if (e.act !== "offer" && e.act !== "evaluate" && !offered.has(e.rid)) status = "needs an offer first";
    else if (e.act === "close" && k.mine) status = "he's already yours";
    if (status === "runs") {
      if (used + cost > avail) status = "cut: out of hours";
      else { used += cost; if (e.act === "offer") offered.add(e.rid); }
    }
    return { e, status, cost };
  });
  return { used, avail, rows, notes };
}

// ═══ Shell ═════════════════════════════════════════════════════════════════

function renderWho() {
  const w = $("#whoami");
  if (S.B) {
    w.innerHTML = `<span>${esc(S.B.team)}${S.B.owner ? ` · @${esc(S.B.owner)}` : ""}</span><button type="button" id="logout">Log out</button>`;
    $("#logout").onclick = logout;
  } else {
    w.innerHTML = `<a href="#/login" style="color:inherit">Log in</a>`;
  }
  const t = $("#theme-toggle");
  if (t) t.remove();
  const tb = document.createElement("button");
  tb.id = "theme-toggle"; tb.type = "button"; tb.textContent = "Light / dark";
  tb.onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next; store.set("cc-theme", next);
  };
  w.appendChild(tb);
}

function renderStrip() {
  const m = S.manifest;
  const due = [];
  const names = { rec: "recruiting", depth: "depth chart", plan: "game plan", calls: "play-calling", jobs: "jobs", staff: "staff", money: "money", nil: "NIL raises and the draft", portal: "the portal", roster: "roster week", spring: "spring" };
  m.sections.forEach((s) => due.push(names[s] || s));
  $("#strip").innerHTML = `<div class="strip-inner"><span class="cycle">Cycle ${m.cycle}</span>
    <span>${esc(m.label)}</span>
    <span class="due">${due.length ? `Orders open: <b>${esc(due.join(", "))}</b>` : esc(m.note || "No orders this cycle.")}</span>
    ${m.note && due.length ? `<span class="due">${esc(m.note)}</span>` : ""}
    ${m.formUrl ? `<a href="${esc(m.formUrl)}" target="_blank" rel="noopener">Submit your code</a>` : ""}</div>`;
}

function setNav(route) {
  document.querySelectorAll("#nav a").forEach((a) => {
    const h = a.getAttribute("href").slice(2);
    a.classList.toggle("on", h === "" ? route === "" : route.startsWith(h));
  });
}

function showMeter(on) {
  const m = $("#meter");
  if (!on || !S.B || !S.manifest.sections.includes("rec")) { m.hidden = true; return; }
  const p = planHours();
  const pct = p.avail ? Math.min(100, (p.used / p.avail) * 100) : 0;
  const over = p.rows.some((r) => r.status.startsWith("cut"));
  m.hidden = false;
  m.innerHTML = `<div class="meter-inner">
    <div class="field-bar ${over ? "over" : ""}" role="meter" aria-valuemin="0" aria-valuemax="${p.avail}" aria-valuenow="${p.used}" aria-label="Recruiting hours">
      <div class="fill" style="width:${pct}%"></div><div class="lines"></div>
      <div class="label"><span>${p.used} of ${p.avail} hours<span class="long"> this week</span></span><span class="long">${over ? "some orders will be cut" : `${p.avail - p.used} left`}</span></div>
    </div>
    <a class="btn go" href="#/my/code">Build my code</a></div>`;
}

// ═══ Router ════════════════════════════════════════════════════════════════

const routes = [
  [/^$/, viewHome], [/^scores(?:\/(\d+))?$/, viewScores], [/^standings$/, viewStandings], [/^polls$/, viewPolls],
  [/^recruits$/, viewRecruits], [/^recruit\/(\d+)$/, viewRecruit], [/^teams$/, viewTeams], [/^team\/([\w-]+)$/, viewTeam],
  [/^game\/(\d+)\/(\d+)$/, viewGame], [/^player\/([\w-]+)\/(\d+)$/, viewPlayer], [/^directory$/, viewDirectory], [/^jobs$/, viewJobs], [/^guide$/, viewGuide], [/^login$/, viewLogin], [/^my\/player\/(\d+)$/, viewMyPlayer], [/^my(?:\/(\w+))?$/, viewMy],
];

async function route() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  const [path, query] = h.split("?");
  setNav(path.startsWith("game/") ? "scores" : path.startsWith("player/") ? "teams" : path);
  showMeter(false);
  for (const [re, fn] of routes) {
    const m = path.match(re);
    if (m) {
      try { await fn(...m.slice(1), new URLSearchParams(query || "")); }
      catch (e) { app().innerHTML = `<div class="note bad">${esc(e.message || e)}</div>`; console.error(e); }
      window.scrollTo(0, 0);
      return;
    }
  }
  app().innerHTML = `<p class="empty">That page doesn't exist. <a href="#/">Go to the home page</a>.</p>`;
}

// ═══ Public pages ══════════════════════════════════════════════════════════

function gameCard(g) {
  const played = g.played;
  const awayWon = played && g.a > g.h;
  return `<div class="game">
    <div class="row ${played && awayWon ? "won" : ""}"><span>${rk(g.ar)}${teamLink(g.away)}</span><span class="sc">${played ? g.a : ""}</span></div>
    <div class="row ${played && !awayWon ? "won" : ""}"><span>${g.neutral ? "" : "@ "}${rk(g.hr)}${teamLink(g.home)}</span><span class="sc">${played ? g.h : ""}</span></div>
    ${g.name || g.box || !played ? `<div class="meta">${g.name ? esc(g.name) : played ? "" : "Upcoming"}${g.box ? `${g.name ? " · " : ""}<a href="#/game/${g.w}/${g.gi}">Box score</a>` : ""}</div>` : ""}</div>`;
}
function rankedFirst(games) {
  return [...games].sort((a, b) => Math.min(a.hr || 99, a.ar || 99) - Math.min(b.hr || 99, b.ar || 99));
}

async function viewHome() {
  const [scores, polls, news] = await Promise.all([getJSON("scores.json"), getJSON("polls.json"), getJSON("news.json")]);
  const m = S.manifest;
  const last = [...scores].reverse().find((w) => w.games.some((g) => g.played));
  const next = scores.find((w) => w.games.some((g) => !g.played));
  const mine = S.B ? `<section class="panel"><h3>${esc(S.B.team)} this week</h3>
      <p>${S.B.gameday.next ? `Next: ${S.B.gameday.next.site === "away" ? "at" : "vs"} ${esc(S.B.gameday.next.opp)}, Week ${S.B.gameday.next.week}.` : "No game this week."}</p>
      <p>${S.B.recruiting.hours.total} recruiting hours, ${S.draft.queue.length} standing orders, ${S.draft.board.length} recruits on the board.</p>
      <a class="btn go" href="#/my/recruiting">Work my board</a></section>` : `<section class="panel"><h3>Coaching a program?</h3><p>Log in with your team's password to see your roster, work your recruiting board and build this week's code.</p><a class="btn go" href="#/login">Log in</a></section>`;
  app().innerHTML = `<h1>${esc(m.title)}</h1><p class="muted">${esc(m.status)}</p>
    <div class="grid" style="margin-top:18px">
      <section class="wide">${mine}</section>
      <section class="wide"><h2>${last ? esc(last.label) : "This week"}</h2>
        <div class="games">${(last ? rankedFirst(last.games.filter((g) => g.played)) : (next ? rankedFirst(next.games) : [])).slice(0, 12).map(gameCard).join("")}</div>
        <p style="margin-top:8px"><a href="#/scores">All scores</a></p></section>
      <section><h2>Poll</h2><p class="quiet">${esc(polls.label)}</p>${pollTable(polls.poll.slice(0, 10))}<p><a href="#/polls">Full top 25</a></p></section>
      <section><h2>Headlines</h2>${news.headlines.length ? `<ul>${news.headlines.map((h) => `<li>${esc(h)}</li>`).join("")}</ul>` : `<p class="muted">No headlines yet.</p>`}
        ${news.recruiting.length ? `<h3 style="margin-top:16px">Recruiting wire</h3><ul>${news.recruiting.slice(0, 8).map((h) => `<li>${esc(h)}</li>`).join("")}</ul>` : ""}</section>
    </div>`;
}

function pollTable(rows) {
  return `<div class="table-wrap"><table><thead><tr><th class="tight">#</th><th>Team</th><th class="r">Record</th><th class="r">Move</th></tr></thead><tbody>
    ${rows.map((r) => `<tr><td class="num">${r.rank}</td><td>${teamLink(r.id)}</td><td class="r num">${esc(r.record)}</td>
      <td class="r quiet">${r.new ? "new" : r.move ? (r.move > 0 ? `up ${r.move}` : `down ${-r.move}`) : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

async function viewScores(week) {
  const scores = await getJSON("scores.json");
  const played = scores.filter((w) => w.games.some((g) => g.played));
  const def = played.length ? played[played.length - 1].week : (scores[0] || {}).week;
  const wk = Number(week || def);
  const w = scores.find((x) => x.week === wk) || scores[0];
  app().innerHTML = `<h1>Scores</h1>
    <div class="weekpick" style="margin-top:14px">${scores.map((x) => `<a class="chip ${x.week === wk ? "on" : ""}" href="#/scores/${x.week}">${esc(x.label)}</a>`).join("")}</div>
    ${w ? `<div class="games">${rankedFirst(w.games).map(gameCard).join("")}</div>` : `<p class="empty">No games scheduled yet.</p>`}`;
}

async function viewStandings() {
  const st = await getJSON("standings.json");
  app().innerHTML = `<h1>Standings</h1><div class="grid" style="margin-top:18px">${st.map((c) => `<section>
    <h2><span class="conf-tag" style="background:${esc((S.manifest.teams.find((t) => t.conf === c.conf) || {}).color)}"></span>${esc(c.name)}</h2>
    <div class="table-wrap"><table><thead><tr><th>Team</th><th class="r">Conf</th><th class="r">Overall</th></tr></thead><tbody>
    ${c.rows.map((r) => `<tr class="${S.B && S.B.id === r.id ? "mine" : ""}"><td>${rk(r.rank)}${teamLink(r.id)}</td><td class="r num">${esc(r.conf)}</td><td class="r num">${esc(r.all)}</td></tr>`).join("")}
    </tbody></table></div></section>`).join("")}</div>`;
}

async function viewPolls() {
  const [p, cls] = await Promise.all([getJSON("polls.json"), getJSON("classes.json").catch(() => [])]);
  app().innerHTML = `<h1>Polls</h1><p class="muted">${esc(p.label)}</p><div class="grid" style="margin-top:18px">
    <section><h2>Media top 25</h2>${pollTable(p.poll)}</section>
    ${p.cfp.length ? `<section><h2>Playoff committee</h2><div class="table-wrap"><table><tbody>${p.cfp.map((r) => `<tr><td class="num tight">${r.rank}</td><td>${teamLink(r.id)}</td></tr>`).join("")}</tbody></table></div></section>` : ""}
    ${cls.length ? `<section><h2>Recruiting classes</h2><div class="table-wrap"><table><thead><tr><th class="tight">#</th><th>Team</th><th class="r">Commits</th><th class="r">Avg</th><th class="r">5★/4★</th></tr></thead><tbody>${cls.slice(0, 25).map((c) => `<tr class="${S.B && S.B.id === c.id ? "mine" : ""}"><td class="num">${c.rank || ""}</td><td>${teamLink(c.id)}</td><td class="r num">${c.n}</td><td class="r num">${c.avg.toFixed(2)}</td><td class="r num">${c.five}/${c.four}</td></tr>`).join("")}</tbody></table></div></section>` : ""}
    ${p.heisman.length ? `<section><h2>Award watch</h2><div class="table-wrap"><table><tbody>${p.heisman.map((h, i) => `<tr><td class="num tight">${i + 1}</td><td>${esc(h.name)}</td><td>${esc(h.pos)}</td><td>${esc(h.school)}</td></tr>`).join("")}</tbody></table></div></section>` : ""}
    </div>`;
}

function statusOf(r) {
  if (r.sg) return `<span class="tag good">Signed: ${esc(team(r.c).school || "")}</span>`;
  if (r.c) return `<span class="tag">Committed: ${teamLink(r.c)}</span>`;
  return `<span class="quiet">Open</span>`;
}

function scanMap() {
  if (!S.B) return null;
  if (!S.B._scan) { S.B._scan = {}; (S.B.recruiting.scan || []).forEach((x) => (S.B._scan[x[0]] = { proj: x[1], st: x[2], fit: x[3], why: x[4] })); }
  return S.B._scan;
}
const FIT_TAG = { "IN-STATE": "good", "REGION": "good", "SCHEME FIT": "good", "INTERESTED": "good", "SLEEPER": "warn", "REACH": "warn",
  "STAFF PRIORITY": "warn", "HARD SELL": "bad", "COMMITTED": "", "OUT OF REGION": "" };
const fitTags = (why) => (why || []).map((w) => `<span class="tag ${w.startsWith("NEED") ? "bad" : FIT_TAG[w] || ""}">${esc(w)}</span>`).join(" ");

async function viewRecruits(q) {
  const all = await loadRecruits();
  const sc = scanMap();
  const f = {
    text: q.get("q") || "", pos: q.get("pos") || "", st: q.get("st") || "", stars: q.get("stars") || "",
    status: q.get("status") || "", board: q.get("board") === "1", page: Number(q.get("page") || 1),
    sort: q.get("sort") || (S.B ? "fit" : "rank"),
  };
  const states = [...new Set(all.map((r) => r.st))].sort();
  const board = S.draft ? new Set(S.draft.board) : new Set();
  let rows = all.filter((r) =>
    (!f.text || r.n.toLowerCase().includes(f.text.toLowerCase()) || (r.hs || "").toLowerCase().includes(f.text.toLowerCase())) &&
    (!f.pos || r.p === f.pos) && (!f.st || r.st === f.st) && (!f.stars || String(r.s) === f.stars) &&
    (!f.status || (f.status === "open" ? !r.c : !!r.c)) && (!f.board || board.has(r.id)));
  const PROJ_ORDER = ["AA", "STAR", "QS", "STR", "ROT", "BU", "DEV", "LS"];
  const projKey = (r) => { const p = sc && sc[r.id] ? sc[r.id].proj.split("-") : ["LS"]; return PROJ_ORDER.indexOf(p[p.length - 1]) * 10 + PROJ_ORDER.indexOf(p[0]); };
  if (sc && f.sort === "fit") rows = [...rows].sort((a, b) => ((sc[b.id] || {}).fit ?? -99) - ((sc[a.id] || {}).fit ?? -99));
  else if (sc && f.sort === "proj") rows = [...rows].sort((a, b) => projKey(a) - projKey(b) || (a.r || 99999) - (b.r || 99999));
  const per = 50, pages = Math.max(1, Math.ceil(rows.length / per)), page = Math.min(f.page, pages);
  const shown = rows.slice((page - 1) * per, page * per);
  const qs = (o) => "#/recruits?" + new URLSearchParams({ ...{ q: f.text, pos: f.pos, st: f.st, stars: f.stars, status: f.status, board: f.board ? "1" : "", sort: f.sort, page: String(page) }, ...o }).toString();
  app().innerHTML = `<h1>Recruits</h1><p class="muted">${all.length.toLocaleString()} prospects in this class. Stars and rankings are public. ${S.B ? "Projection is your staff's read: the more you evaluate him, the tighter it gets." : "Log in to see your staff's projection and where you stand."}</p>
    <form class="controls" id="rf" style="margin-top:14px">
      <input type="text" name="q" placeholder="Name or high school" value="${esc(f.text)}" aria-label="Search">
      <select name="pos" aria-label="Position"><option value="">All positions</option>${S.rules.positions.map((p) => `<option ${p === f.pos ? "selected" : ""}>${p}</option>`).join("")}</select>
      <select name="stars" aria-label="Stars"><option value="">All stars</option>${[5, 4, 3, 2, 1].map((s) => `<option value="${s}" ${String(s) === f.stars ? "selected" : ""}>${s} star</option>`).join("")}</select>
      <select name="st" aria-label="State"><option value="">All states</option>${states.map((s) => `<option ${s === f.st ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
      <select name="status" aria-label="Status"><option value="">Open and committed</option><option value="open" ${f.status === "open" ? "selected" : ""}>Still open</option><option value="committed" ${f.status === "committed" ? "selected" : ""}>Committed</option></select>
      ${S.B ? `<select name="sort" aria-label="Sort"><option value="fit" ${f.sort === "fit" ? "selected" : ""}>Suggested for you</option><option value="rank" ${f.sort === "rank" ? "selected" : ""}>National rank</option><option value="proj" ${f.sort === "proj" ? "selected" : ""}>Your projection</option></select>
        <label><input type="checkbox" name="board" value="1" ${f.board ? "checked" : ""}> My board only</label>` : ""}
      <button class="btn" type="submit">Show</button>
    </form>
    <div class="table-wrap"><table><thead><tr><th class="tight">Rank</th><th>Name</th><th>Pos</th><th>Stars</th>${S.B ? "<th>Proj</th>" : ""}<th>Size</th><th>From</th><th>Status</th><th class="r">Offers</th>${S.B ? "<th>You</th><th>Why</th><th></th>" : ""}</tr></thead><tbody>
    ${shown.map((r) => {
      const x = sc ? sc[r.id] || {} : {};
      return `<tr class="${board.has(r.id) ? "mine" : ""}"><td class="num">${r.r || ""}</td><td><a href="#/recruit/${r.id}">${esc(r.n)}</a>${r.k !== "hs" ? ` <span class="tag">${r.k === "juco" ? "JUCO" : "Intl"}</span>` : ""}</td>
        <td>${r.p}</td><td>${stars(r.s)}</td>${S.B ? `<td class="num">${esc(x.proj || "")}</td>` : ""}<td class="quiet">${esc(r.ht)} ${r.wt || ""}</td><td>${esc(r.st)}<span class="quiet"> ${esc(r.hs)}</span></td><td>${statusOf(r)}</td><td class="r num">${r.of.length}</td>
        ${S.B ? `<td class="quiet">${esc(x.st || "no contact")}</td><td class="tags">${fitTags(x.why)}</td><td>${S.manifest.sections.includes("rec") && !r.sg ? `<button class="btn small" data-board="${r.id}">${board.has(r.id) ? "Remove" : "Add to board"}</button>` : ""}</td>` : ""}</tr>`;
    }).join("") || `<tr><td colspan="12" class="empty">No recruits match. Clear a filter.</td></tr>`}
    </tbody></table></div>
    ${S.B ? `<p class="quiet" style="margin-top:8px">Proj: LS long shot · DEV developmental · BU backup · ROT rotation · STR starter · QS quality starter · STAR · AA All-American</p>` : ""}
    <div class="pager"><a class="btn small ${page <= 1 ? "ghost" : ""}" href="${qs({ page: String(Math.max(1, page - 1)) })}">Previous</a><span class="quiet">Page ${page} of ${pages} · ${rows.length.toLocaleString()} recruits</span><a class="btn small ${page >= pages ? "ghost" : ""}" href="${qs({ page: String(Math.min(pages, page + 1)) })}">Next</a></div>`;
  $("#rf").onsubmit = (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    location.hash = "#/recruits?" + new URLSearchParams({ q: fd.get("q") || "", pos: fd.get("pos") || "", st: fd.get("st") || "", stars: fd.get("stars") || "", status: fd.get("status") || "", board: fd.get("board") ? "1" : "", sort: fd.get("sort") || f.sort, page: "1" });
  };
  app().onclick = (ev) => {
    const b = ev.target.closest("[data-board]");
    if (!b) return;
    toggleBoard(Number(b.dataset.board));
    viewRecruits(q);
  };
}

function toggleBoard(rid) {
  const d = S.draft;
  const i = d.board.indexOf(rid);
  if (i >= 0) { d.board.splice(i, 1); d.queue = d.queue.filter((e) => e.rid !== rid); }
  else if (d.board.length >= S.rules.boardMax) { alert(`Your board holds ${S.rules.boardMax}. Remove someone first.`); return; }
  else d.board.push(rid);
  saveDraft();
}

const money = (n) => (n >= 1e6 ? `$${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M` : n >= 1000 ? `$${Math.round(n / 1000)}K` : `$${n || 0}`);

async function recruitDetail(id) {
  try { return (await getJSON(`rd/${Number(id) % 16}.json`))[id] || {}; } catch (e) { return {}; }
}

async function viewRecruit(id) {
  await loadRecruits();
  const r = S.recById[Number(id)];
  if (!r) { app().innerHTML = `<p class="empty">That recruit isn't in this class.</p>`; return; }
  const D = await recruitDetail(r.id);
  const k = known(r.id);
  const x = (scanMap() || {})[r.id] || {};
  const onBoard = S.draft && S.draft.board.includes(r.id);
  const open = S.B && S.manifest.sections.includes("rec") && !r.sg;
  const first = esc(r.n.split(" ")[0]);
  const facts = [];
  if (D.or) facts.push(`<li><span class="k">From</span>${esc(D.or)}, ${esc(r.st)}</li>`);
  if (D.ss) facts.push(`<li><span class="k">${D.hsk === "hs" ? "Senior season" : "This season"}</span>${esc(D.ss)}</li>`);
  facts.push(`<li><span class="k">Official visits</span>${D.ov && D.ov.length ? D.ov.map(([t, w]) => `${teamLink(t)} (Wk ${w})`).join(", ") : "none yet"} <span class="quiet">(${(D.ov || []).length} of ${S.rules.ovMax})</span></li>`);
  if (D.cb) facts.push(`<li><span class="k">Crystal ball</span>${teamLink(D.cb[0])} ${D.cb[1]}%</li>`);
  if (D.cw) facts.push(`<li><span class="k">Commitment</span>${esc(D.cw)}</li>`);
  let staff = "";
  if (S.B) {
    const d = S.draft;
    const pri = Object.entries(S.rules.priorities);
    const race = k && k.race && k.race.length ? k.race : null;
    const top = race ? Math.max(...race.map((z) => z[1]), 1) : 1;
    const nil = (k && k.nilPanel) || null;
    staff = `<div class="grid" style="margin-top:22px">
      <section class="panel"><h2>Scouting report</h2>
        <p>Projection: <b>${esc(k ? k.projWords : "")}</b>${k && k.proj ? ` <span class="quiet">(${esc(k.proj)})</span>` : ""}</p>
        <p class="quiet">Scouted ${k ? k.scout : 0} of 3. Every evaluation tightens the read; it shows after the week is played.</p>
        <h3 style="margin-top:12px">What he wants</h3>
        <ol>${(k ? k.wants : [null, null, null]).map((w) => w ? `<li><b>${esc(w)}</b></li>` : `<li class="quiet">??? (evaluate him, or pitch it and see)</li>`).join("")}</ol>
        ${k && k.reads ? `<p>Reads as: <b>${esc(k.reads)}</b></p>` : ""}
        ${x.why && x.why.length ? `<p>${fitTags(x.why)}</p>` : ""}
        ${k && k.pipeline ? `<p>Pipeline at ${esc(r.hs)}: <b>${esc(k.pipeline)}</b></p>` : ""}
      </section>
      <section class="panel"><h2>The race</h2>
        <p>You: <b>${esc(k ? k.standing : "No contact yet")}</b> · offer ${k && k.offered ? `<span class="tag good">yes</span>` : `<span class="tag bad">no</span>`} · ${r.of.length} offers out</p>
        ${race ? `<div class="race">${race.map(([t, v]) => `<div class="race-row ${t === S.B.id ? "me" : ""}"><span>${teamLink(t)}</span><span class="bar"><i style="width:${Math.round((v / top) * 100)}%"></i></span><span class="num">${v}</span></div>`).join("")}</div>
          <p class="quiet">Interest runs 0 to 100.${top < 25 ? " Early days: nobody has a real hold yet." : ""}</p>` : `<p class="muted">Nobody's in on him yet.</p>`}
        ${k && k.warn ? `<div class="note bad">${esc(k.warn)}</div>` : ""}
      </section>
      <section class="panel"><h2>NIL</h2>
        ${nil ? `<p>Market for a ${r.s}-star: about <b>${money(nil.market)}/yr</b> <span class="quiet">(budgets like yours pay about ${money(nil.yours)})</span></p>
        <p>Your offer: <b>${k.nil ? money(k.nil) + "/yr" : "none"}</b> · free to offer ${money(S.B.recruiting.nilLeft)}</p>
        <p>${nil.others ? `Other NIL offers: ${nil.others}, reportedly as high as ${money(nil.high)}/yr (${teamLink(nil.highBy)})` : "Nobody else has put NIL money on the table."}</p>
        <p class="quiet">${esc(nil.appetite || "Evaluate him to find out how much money matters to him.")}</p>` : `<p class="muted">Work him first to learn the NIL picture.</p>`}
      </section>
      <section class="panel"><h2>His room</h2><p>${esc(k ? k.room : "")}</p>
        ${k && k.promise ? `<p>Your promise: <b>${esc((S.rules.promises[k.promise] || {}).label || k.promise)}</b></p>` : ""}
        ${k && k.pitches && k.pitches.length ? `<h3 style="margin-top:12px">Your pitch</h3><table><tbody>${k.pitches.map(([p, w]) => `<tr><td>${esc(S.rules.priorities[p] || p)}${k.knowsKeys.includes(p) ? ` <span class="tag good">he cares</span>` : ""}</td><td class="quiet">${esc(w)}</td></tr>`).join("")}</tbody></table>` : ""}
      </section>
    </div>
    ${k && k.log.length ? `<section style="margin-top:20px"><h2>Your history with ${first}</h2><ul>${k.log.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></section>` : ""}
    ${open ? `<section class="panel" style="margin-top:22px"><h2>Orders on ${first}</h2>
      <div class="controls"><button class="btn ${onBoard ? "" : "go"}" id="tb">${onBoard ? "Remove from board" : "Add to board"}</button></div>
      ${onBoard ? `<h3 style="margin-top:14px">Add a standing order</h3>
      <div class="controls"><select id="qa">${Object.entries(S.rules.actions).map(([a, v]) => `<option value="${a}">${esc(v.label)} (${S.B.recruiting.costs[a]}h)</option>`).join("")}</select>
        <select id="qr">${Object.entries(S.rules.queueRules).map(([a, v]) => `<option value="${a}">${esc(v.replace("{n}", "N"))}</option>`).join("")}</select>
        <select id="qp"><option value="auto">Pitch: best we know</option>${pri.map(([a, v]) => `<option value="${a}">Pitch: ${esc(v)}</option>`).join("")}</select>
        <button class="btn" id="qadd">Add to queue</button></div>
      <h3 style="margin-top:14px">This week only</h3>
      <div class="controls">
        <select id="ovw" ${(k && k.canOv) || d.queue.some((e) => e.rid === r.id && e.act === "offer") ? "" : "disabled"}><option value="">Official visit: none</option>${S.B.recruiting.homeGames.map((g) => `<option value="${g.week}" ${d.ov[r.id] == g.week ? "selected" : ""}>Week ${g.week} vs ${esc(g.opp)}</option>`).join("")}</select>
        <label>NIL $/yr <input type="number" id="nil" min="0" step="5000" value="${d.nil[r.id] ?? (k ? k.nil : 0)}"></label>
        <select id="prom" ${k && k.promise ? "disabled" : ""}><option value="">Promise: none</option>${Object.entries(S.rules.promises).map(([a, v]) => `<option value="${a}" ${d.prom[r.id] === a ? "selected" : ""}>${esc(v.label)} (${v.cost}h)</option>`).join("")}</select>
        ${S.B.recruiting.pwoOpen && r.s <= 2 ? `<label><input type="checkbox" id="pwo" ${d.pwo.includes(r.id) ? "checked" : ""}> Preferred walk-on</label>` : ""}
        <button class="btn" id="once">Save</button></div>
      ${k && k.whyOv && !k.canOv ? `<p class="quiet">Visit: ${esc(k.whyOv)}</p>` : ""}${k && k.whyPromise ? `<p class="quiet">Promise: ${esc(k.whyPromise)}</p>` : ""}` : ""}
    </section>` : ""}`;
  }
  app().innerHTML = `<p><a href="#/recruits">Recruits</a></p><h1>${esc(r.n)}${D.gen ? ` <span class="tag warn">Generational</span>` : ""}</h1>
    <p class="muted">${r.p} · ${stars(r.s)} · ${r.r ? `No. ${r.r} nationally, ${r.pr} at ${r.p}` : "unranked"} · ${esc(r.ht)} ${r.wt || ""} · ${esc(r.hs)} (${esc(r.st)})</p>
    <p>${statusOf(r)}</p>
    <ul class="facts">${facts.join("")}</ul>
    <div class="grid" style="margin-top:16px">
      <section><h2>Offers</h2>${r.of.length ? `<div class="schools">${r.of.map(teamLink).join("")}</div>` : `<p class="muted">No offers yet.</p>`}</section>
      <section><h2>Top schools</h2>${r.top.length ? `<ol>${r.top.map((t) => `<li>${teamLink(t)}</li>`).join("")}</ol>` : `<p class="muted">No favorites yet.</p>`}</section>
    </div>${staff}`;
  if (!open) return;
  $("#tb").onclick = () => { toggleBoard(r.id); viewRecruit(id); };
  const add = $("#qadd");
  if (add) add.onclick = () => {
    const rule = $("#qr").value;
    S.draft.queue.push({ rid: r.id, act: $("#qa").value, rule, n: rule === "weeks" ? 2 : 0, pitch: $("#qp").value, last: null });
    saveDraft(); location.hash = "#/my/recruiting";
  };
  const once = $("#once");
  if (once) once.onclick = () => {
    const d = S.draft, ov = $("#ovw").value, nil = Number($("#nil").value || 0), pr = $("#prom").value, pw = $("#pwo");
    if (ov) d.ov[r.id] = Number(ov); else delete d.ov[r.id];
    if (nil !== (k ? k.nil : 0)) d.nil[r.id] = nil; else delete d.nil[r.id];
    if (pr) d.prom[r.id] = pr; else delete d.prom[r.id];
    if (pw) { d.pwo = d.pwo.filter((x) => x !== r.id); if (pw.checked) d.pwo.push(r.id); }
    saveDraft(); viewRecruit(id);
  };
}

async function viewTeams() {
  const by = {};
  S.manifest.teams.forEach((t) => (by[t.confName] = by[t.confName] || []).push(t));
  app().innerHTML = `<h1>Teams</h1><div class="grid" style="margin-top:18px">${Object.entries(by).sort().map(([c, ts]) => `<section><h2><span class="conf-tag" style="background:${esc(ts[0].color)}"></span>${esc(c)}</h2>
    <div class="table-wrap"><table><tbody>${ts.map((t) => `<tr><td>${teamLink(t.id)}</td><td class="r num">${esc(t.record)}</td><td class="quiet">${t.owner ? "@" + esc(t.owner) : "CPU"}</td></tr>`).join("")}</tbody></table></div></section>`).join("")}</div>`;
}

async function viewTeam(id) {
  const [T] = await Promise.all([getJSON(`teams/${id}.json`), loadRecruits()]);
  const meta = team(id), c = T.card || {};
  const groups = {};
  T.roster.forEach((p) => (groups[p.p] = groups[p.p] || []).push(p));
  app().innerHTML = `<h1>${esc(meta.school)} ${esc(meta.nick || "")}</h1>
    <p class="muted">${esc(meta.confName)} · ${esc(c.record || meta.record)} (${esc(c.confRecord || meta.confRecord)} conference)${c.rank ? ` · ranked ${c.rank}` : ""} · head coach ${esc(T.coach.name)}${T.coach.record ? ` (${esc(T.coach.record)})` : ""} · ${meta.owner ? "@" + esc(meta.owner) : "CPU program"}</p>
    ${c.looks && c.looks.team ? `<p>Around the league they look <b>${esc(c.looks.team)}</b>: offense ${esc(c.looks.offense || "")}, defense ${esc(c.looks.defense || "")}.</p>` : ""}
    <div class="grid" style="margin-top:18px">
      <section><h2>Schedule</h2><div class="table-wrap"><table><tbody>${(T.schedule || []).map((g) => `<tr><td class="quiet tight">${esc(g.wk)}</td><td>${g.site === "at" ? "at " : ""}${rk(g.oppRank)}${esc(g.opp)}</td><td class="r num">${g.played ? (g.box ? `<a href="#/game/${g.w}/${g.gi}">${g.won ? "W" : "L"} ${esc(g.score)}</a>` : `${g.won ? "W" : "L"} ${esc(g.score)}`) : ""}</td></tr>`).join("")}</tbody></table></div></section>
      <section><h2>Committed</h2>${T.commits.length ? `<ul>${T.commits.map((rid) => { const r = S.recById[rid]; return r ? `<li><a href="#/recruit/${rid}">${esc(r.n)}</a> ${r.p} ${stars(r.s)}</li>` : ""; }).join("")}</ul>` : `<p class="muted">No public commitments yet.</p>`}</section>
      <section class="wide"><h2>Roster</h2><p class="quiet">From the outside you see a rough tier for each player, his traits and his stats. Click a name for his stats and game log. Only his own staff sees more.</p>
        <div class="table-wrap"><table><thead><tr><th class="tight">#</th><th>Name</th><th>Pos</th><th>Class</th><th>Size</th><th>Tier (approx.)</th><th>Traits</th><th>Season</th></tr></thead><tbody>
        ${Object.values(groups).flat().map((p) => `<tr><td class="num">${p.num}</td><td><a href="#/player/${esc(id)}/${p.id}">${esc(p.n)}</a>${p.inj ? ` <span class="tag bad">${esc(p.inj)}</span>` : ""}</td><td>${p.p}</td><td>${esc(p.yr)}</td><td class="quiet">${esc(p.ht)} ${p.wt}</td><td>${esc(p.tier)}</td><td class="traits">${p.traits.map(esc).join(", ")}</td><td class="quiet">${esc(p.stats)}</td></tr>`).join("")}
        </tbody></table></div></section></div>`;
}

// ── box score ──
const pLink = (tid, pid, name) => `<a href="#/player/${esc(tid)}/${pid}">${esc(name)}</a>`;

async function viewGame(w, i) {
  const games = await getJSON(`games/w${w}.json`).catch(() => null);
  const G = games && games[Number(i)];
  if (!G) { app().innerHTML = `<p class="empty">No box score for that game. <a href="#/scores/${esc(w)}">Back to the scores</a>.</p>`; return; }
  const [A, H] = G.teams;
  const nq = Math.max(A.line.length, H.line.length, 4);
  const qh = Array.from({ length: nq }, (_, k) => (k < 4 ? `${k + 1}` : nq === 5 ? "OT" : `OT${k - 3}`));
  const won = (t, o) => (t.score > o.score ? "won" : "");
  const short = (t) => esc(team(t.id).school || t.school);
  const lineRow = (t, o) => `<tr class="${won(t, o)}"><td>${rk(t.rank)}${teamLink(t.id)}</td>${qh.map((_, k) => `<td class="r num">${t.line[k] ?? ""}</td>`).join("")}<td class="r num"><b>${t.score}</b></td></tr>`;
  const catTable = (c, k) => {
    const rows = c.rows[k];
    if (!rows.length) return "";
    return `<div class="table-wrap"><table class="box"><thead><tr><th>${esc(c.name)}</th>${c.cols.map((h) => `<th class="r">${esc(h)}</th>`).join("")}</tr></thead><tbody>
      ${rows.map(([pid, n, pos, ...v]) => `<tr><td>${pLink(G.teams[k].id, pid, n)} <span class="quiet">${esc(pos)}</span></td>${v.map((x) => `<td class="r num">${esc(x)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  };
  const side = (k) => `<section><h2>${short(G.teams[k])}</h2>${G.cats.map((c) => catTable(c, k)).join("") || `<p class="muted">No individual stats recorded.</p>`}</section>`;
  const byQ = {};
  G.scoring.forEach((s) => (byQ[s[0]] = byQ[s[0]] || []).push(s));
  app().innerHTML = `<p><a href="#/scores/${G.w}">${esc(G.label)} scores</a></p>
    <h1 class="boxhead"><span class="${won(A, H)}">${short(A)} ${A.score}</span><span class="quiet">${G.neutral ? "vs" : "at"}</span><span class="${won(H, A)}">${short(H)} ${H.score}</span></h1>
    <p class="muted">${esc(G.label)}${G.name ? ` · ${esc(G.name)}` : ""}${G.neutral ? " · neutral site" : ""}${G.att ? ` · attendance ${Number(G.att).toLocaleString()}` : ""}</p>
    <div class="table-wrap" style="margin-top:14px"><table class="box"><thead><tr><th></th>${qh.map((q) => `<th class="r">${q}</th>`).join("")}<th class="r">T</th></tr></thead>
      <tbody>${lineRow(A, H)}${lineRow(H, A)}</tbody></table></div>
    <div class="grid" style="margin-top:18px">
      <section><h2>Scoring</h2>${G.scoring.length ? Object.entries(byQ).map(([q, list]) => `<h4 class="qhead">${Number(q) <= 4 ? ["", "First", "Second", "Third", "Fourth"][q] + " quarter" : "Overtime"}</h4>
        <div class="table-wrap"><table class="box"><tbody>${list.map(([, clock, tid, text, a, h]) => `<tr><td class="quiet tight num">${esc(clock)}</td><td class="tight">${esc(team(tid).abbr || team(tid).school)}</td><td>${esc(text)}</td>${a === null ? "" : `<td class="r num tight">${a}-${h}</td>`}</tr>`).join("")}</tbody></table></div>`).join("") : `<p class="muted">No scoring.</p>`}</section>
      <section><h2>Team stats</h2><div class="table-wrap"><table class="box"><thead><tr><th></th><th class="r">${short(A)}</th><th class="r">${short(H)}</th></tr></thead><tbody>
        ${G.team.map(([k, a, h]) => `<tr><td>${esc(k)}</td><td class="r num">${esc(a)}</td><td class="r num">${esc(h)}</td></tr>`).join("")}</tbody></table></div></section>
    </div>
    <div class="grid" style="margin-top:18px">${side(0)}${side(1)}</div>
    ${G.drives.length ? `<details style="margin-top:22px"><summary><b>Drive chart</b> <span class="quiet">(${G.drives.length} drives)</span></summary>
      <div class="table-wrap"><table class="box"><thead><tr><th>Team</th><th class="r">Q</th><th class="r">Start</th><th class="r">Own</th><th class="r">Plays</th><th class="r">Yds</th><th class="r">Time</th><th>Result</th></tr></thead><tbody>
      ${G.drives.map(([tid, q, clock, start, plays, yds, time, res]) => `<tr><td>${esc(team(tid).school)}</td><td class="r num">${q}</td><td class="r num">${esc(clock)}</td><td class="r num">${start ?? ""}</td><td class="r num">${plays ?? ""}</td><td class="r num">${yds ?? ""}</td><td class="r num">${esc(time)}</td><td>${esc(res)}</td></tr>`).join("")}</tbody></table></div></details>` : ""}`;
}

// ── any player, from the outside ──
function gameLog(log) {
  if (!log || !log.length) return `<p class="muted">No games played this season.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th class="tight">Week</th><th>Opponent</th><th class="tight">Result</th><th>Line</th></tr></thead><tbody>
    ${log.map(([w, label, gi, opp, site, res, line]) => `<tr><td class="quiet tight">${esc(label)}</td><td>${site === "at" ? "at " : ""}${teamLink(opp)}</td><td class="num tight"><a href="#/game/${w}/${gi}">${esc(res)}</a></td><td>${esc(line) || `<span class="quiet">played</span>`}</td></tr>`).join("")}</tbody></table></div>`;
}

async function viewPlayer(tid, pid) {
  const T = await getJSON(`teams/${tid}.json`).catch(() => null);
  const p = T && T.roster.find((x) => x.id === Number(pid));
  if (!p) { app().innerHTML = `<p class="empty">He isn't on a roster anymore. <a href="#/team/${esc(tid)}">Back to ${esc(team(tid).school || "the team")}</a>.</p>`; return; }
  const mine = S.B && S.B.id === tid;
  app().innerHTML = `<p><a href="#/team/${esc(tid)}">${esc(team(tid).school)} roster</a></p>
    <h1>#${p.num} ${esc(p.n)}</h1>
    <p class="muted">${esc(p.p)} · ${esc(p.yr)} · ${esc(p.ht)}, ${p.wt} lbs${p.home ? ` · ${esc(p.home)}` : ""}${p.stars ? ` · ${stars(p.stars)} recruit` : ""} · ${p.depth === 1 ? "starter" : `No. ${p.depth}`} at ${esc(p.p)}</p>
    ${mine ? `<div class="note good">He's yours. <a href="#/my/player/${p.id}">Open your staff's full card</a> for evaluations, practice and comments.</div>` : ""}
    ${p.inj ? `<div class="note bad">${esc(p.inj)}</div>` : ""}
    <dl class="kv"><div><dt>Tier (approx.)</dt><dd><b>${esc(p.tier)}</b></dd></div><div><dt>Traits</dt><dd>${p.traits.length ? p.traits.map(esc).join(", ") : "none known"}</dd></div>
      <div><dt>Games</dt><dd>${p.gp} this season, ${p.cgp} career</dd></div></dl>
    <section style="margin-top:22px"><h2>${S.manifest.year} season</h2>${p.season.length ? statTables(p.season) : `<p class="muted">No statistics recorded this season.</p>`}</section>
    <section style="margin-top:22px"><h2>Game log</h2>${gameLog(p.log)}</section>
    ${p.career.length ? `<section style="margin-top:22px"><h2>Career · ${p.cgp} games</h2>${statTables(p.career)}
      ${p.years.length ? `<div class="table-wrap" style="margin-top:12px"><table><tbody>${p.years.map(([y, l]) => `<tr><td class="tight num">${y}</td><td>${esc(l)}</td></tr>`).join("")}</tbody></table></div>` : ""}</section>` : ""}`;
}

async function viewDirectory() {
  const ts = S.manifest.teams;
  const by = {};
  ts.forEach((t) => (by[t.confName] = by[t.confName] || []).push(t));
  const n = ts.filter((t) => t.owner).length;
  app().innerHTML = `<h1>League directory</h1><p class="muted">${n} programs have a coach in the league. ${ts.length - n} are open: ask the commissioner to claim one.</p>
    <div class="grid" style="margin-top:18px">${Object.entries(by).sort().map(([c, list]) => `<section><h2>${esc(c)}</h2><div class="table-wrap"><table><tbody>
    ${list.map((t) => `<tr><td>${teamLink(t.id)}</td><td>${t.owner ? "@" + esc(t.owner) : `<span class="tag good">Open</span>`}</td></tr>`).join("")}</tbody></table></div></section>`).join("")}</div>`;
}

// ═══ Log in ════════════════════════════════════════════════════════════════

async function viewLogin() {
  const ts = S.manifest.teams.filter((t) => t.owner);
  app().innerHTML = `<div class="login"><h1>Log in</h1><p class="muted">Pick your program and enter the password the commissioner sent you. It unlocks your team's file right here in your browser; nothing is sent anywhere.</p>
    <form id="lf" style="margin-top:16px">
      <div class="field"><label for="lt">Program</label><select id="lt" required><option value="">Choose your program</option>${ts.map((t) => `<option value="${esc(t.id)}">${esc(t.school)} (@${esc(t.owner)})</option>`).join("")}</select></div>
      <div class="field"><label for="lp">Password</label><input type="password" id="lp" autocomplete="current-password" required placeholder="four words and a number"></div>
      <button class="btn go" type="submit" id="lb">Log in</button><p id="le" class="note bad" hidden></p></form></div>`;
  $("#lf").onsubmit = async (ev) => {
    ev.preventDefault();
    $("#lb").disabled = true; $("#lb").textContent = "Unlocking…"; $("#le").hidden = true;
    try { await login($("#lt").value, $("#lp").value); location.hash = "#/my"; }
    catch (e) { $("#le").hidden = false; $("#le").textContent = e.message; $("#lb").disabled = false; $("#lb").textContent = "Log in"; }
  };
}

// ═══ My team ═══════════════════════════════════════════════════════════════

async function viewMy(tab) {
  if (!S.B) { location.hash = "#/login"; return; }
  await loadRecruits();
  const live = S.manifest.sections;
  tab = tab || (live.includes("portal") ? "portal" : live.includes("roster") ? "rosterweek" : live.includes("spring") ? "spring"
    : live.includes("rec") ? "recruiting" : live.includes("nil") ? "season" : "jobs");
  const tabs = [["recruiting", "Recruiting"], ["gameday", "Game day"], ["roster", "Roster"], ["coach", "Program"], ["staff", "Staff"], ["money", "Money"],
    ...(S.manifest.sections.includes("nil") ? [["season", "Season end"]] : []),
    ...(S.manifest.sections.includes("portal") || (S.B.portal && S.B.portal.mine) ? [["portal", "Portal"]] : []),
    ...(S.manifest.sections.includes("roster") ? [["rosterweek", "Roster week"]] : []),
    ...(S.manifest.sections.includes("spring") || S.B.spring ? [["spring", "Spring"]] : []),
    ["jobs", "Jobs"], ["code", "Code"]];
  const head = `<h1>${esc(S.B.team)}</h1><nav class="subnav" aria-label="My team">${tabs.map(([k, v]) => `<a href="#/my/${k}" class="${k === tab ? "on" : ""}">${v}</a>`).join("")}</nav>`;
  const fn = { recruiting: myRecruiting, gameday: myGameday, roster: myRoster, coach: myCoach, staff: myStaff, money: myMoney, season: mySeason, jobs: myJobs, portal: myPortal, rosterweek: myRosterWeek, spring: mySpring, code: myCode }[tab] || myRecruiting;
  app().innerHTML = head + `<div id="mybody"></div>`;
  fn($("#mybody"));
  showMeter(tab !== "code");
}

function rerender(tabFn) { tabFn($("#mybody")); showMeter(true); }

function myRecruiting(el) {
  const B = S.B, d = S.draft, R = B.recruiting, open = S.manifest.sections.includes("rec");
  const p = planHours();
  const lw = R.lastWeek || {};
  const name = (rid) => (S.recById[rid] || {}).n || `#${rid}`;
  const pitchOpts = (e) => {
    const k = known(e.rid);
    const keys = k ? k.knowsKeys : [];
    const all = Object.entries(S.rules.priorities);
    return `<option value="auto">Best we know</option>` + all.map(([a, v]) => `<option value="${a}" ${e.pitch === a ? "selected" : ""}>${esc(v)}${keys.includes(a) ? " (he cares)" : ""}</option>`).join("");
  };
  el.innerHTML = `
    ${!open ? `<div class="note">${esc(S.manifest.note || "Recruiting orders aren't open this cycle.")}</div>` : ""}
    <p class="muted">${R.hours.phase} week: <b>${R.hours.total}</b> staff hours${d.plan.focus === "recruit" ? ` plus ${S.rules.focus.recruit.hours} from a recruiting-week practice plan` : ""}. Orders run top to bottom; anything that doesn't fit is cut. What your staff learns shows up after the week is played.</p>
    ${R.class ? `<div class="kv-strip"><span>Class rank <b>${R.class.rank ? "No. " + R.class.rank : "unranked"}</b></span><span>Commits <b>${R.classSize}${R.class.cap ? " of " + R.class.cap : ""}</b></span><span>Average <b>${R.class.avg ? R.class.avg.toFixed(2) + "★" : "none"}</b></span><span>NIL free <b>${money(R.nilLeft)}</b></span><span class="quiet">${esc(R.class.needs)}</span></div>` : ""}
    ${lw.week ? `<div class="note good">Last week: ${lw.ran.length} orders ran${lw.cut.length ? `, ${lw.cut.length} cut for hours` : ""}${lw.done.length ? `, ${lw.done.length} finished` : ""}.</div>` : ""}
    <section><h2>Standing orders</h2>
      <div id="queue">${d.queue.length ? p.rows.map((r, i) => `<div class="queue-row ${r.status === "runs" ? "" : "cut"}">
        <span class="pos">${i + 1}</span>
        <span><a href="#/recruit/${r.e.rid}">${esc(name(r.e.rid))}</a><br><span class="quiet">${esc(r.status)}${r.status === "runs" ? `, ${r.cost}h` : ""}</span></span>
        <select data-q="${i}" data-f="act" ${open ? "" : "disabled"} aria-label="Action">${Object.entries(S.rules.actions).map(([a, v]) => `<option value="${a}" ${a === r.e.act ? "selected" : ""}>${esc(v.label)} (${B.recruiting.costs[a]}h)</option>`).join("")}</select>
        <span class="weeks"><select data-q="${i}" data-f="rule" ${open ? "" : "disabled"} aria-label="Repeat">${Object.entries(S.rules.queueRules).map(([a, v]) => `<option value="${a}" ${a === r.e.rule ? "selected" : ""}>${esc(v.replace("{n}", "N"))}</option>`).join("")}</select>
          ${r.e.rule === "weeks" ? `<input type="number" min="1" max="20" value="${r.e.n || 1}" data-q="${i}" data-f="n" aria-label="Weeks" style="width:64px">` : ""}</span>
        <select data-q="${i}" data-f="pitch" ${open ? "" : "disabled"} aria-label="Pitch">${pitchOpts(r.e)}</select>
        <span class="ops">${open ? `<button class="iconbtn" data-move="${i}" data-dir="-1" ${i === 0 ? "disabled" : ""} aria-label="Move up">↑</button><button class="iconbtn" data-move="${i}" data-dir="1" ${i === d.queue.length - 1 ? "disabled" : ""} aria-label="Move down">↓</button><button class="iconbtn" data-del="${i}" aria-label="Remove">✕</button>` : ""}</span>
      </div>`).join("") : `<p class="empty">No standing orders yet. Open a recruit on your board to add one.</p>`}</div>
    </section>
    <section><h2>Coordinators on autopilot</h2><p class="quiet">They work their side of your board with the hours left after your orders.</p>
      <div class="controls">${["OC", "DC"].map((r) => `<label><input type="checkbox" data-auto="${r}" ${d.auto[r][0] ? "checked" : ""} ${open ? "" : "disabled"}> ${r === "OC" ? "Offense" : "Defense"} (${r})</label>
        <label>up to <input type="number" min="0" max="60" data-autoh="${r}" value="${d.auto[r][1]}" ${open ? "" : "disabled"}> hours</label>`).join("")}</div></section>
    <section><h2>Your board <span class="quiet">${d.board.length} of ${S.rules.boardMax}</span></h2>
      <p class="quiet">Find prospects on the <a href="#/recruits">recruits page</a> and add them. Open a name to queue orders, set a visit, NIL or a promise.</p>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Pos</th><th>Stars</th><th>Status</th><th>Where you stand</th><th>Staff projection</th><th>He cares about</th><th></th></tr></thead><tbody>
      ${d.board.map((rid) => { const r = S.recById[rid] || {}; const k = known(rid) || {}; return `<tr><td><a href="#/recruit/${rid}">${esc(r.n)}</a></td><td>${r.p || ""}</td><td>${stars(r.s)}</td><td>${r.c ? statusOf(r) : `<span class="quiet">Open</span>`}</td>
        <td>${esc(k.standing || "No contact yet")}${k.offered ? ` <span class="tag good">offered</span>` : ""}${d.ov[rid] ? ` <span class="tag">visit wk ${d.ov[rid]}</span>` : k.ov ? ` <span class="tag">visit wk ${k.ov}</span>` : ""}</td>
        <td>${esc(((scanMap() || {})[rid] || {}).proj || "")}${k.proj ? ` <span class="quiet">${esc(k.proj)}</span>` : ""}</td><td class="quiet">${(k.knows || []).map(esc).join(", ")}</td>
        <td>${open ? `<button class="btn small ghost" data-rm="${rid}">Remove</button>` : ""}</td></tr>`; }).join("") || `<tr><td colspan="8" class="empty">Your board is empty.</td></tr>`}
      </tbody></table></div></section>`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.dataset.q !== undefined) {
      const e = d.queue[Number(t.dataset.q)];
      e[t.dataset.f] = t.dataset.f === "n" ? Math.max(1, Math.min(20, Number(t.value) || 1)) : t.value;
      if (t.dataset.f === "rule" && t.value === "weeks" && !e.n) e.n = 2;
    } else if (t.dataset.auto) d.auto[t.dataset.auto][0] = t.checked;
    else if (t.dataset.autoh) d.auto[t.dataset.autoh][1] = Math.max(0, Math.min(60, Number(t.value) || 0));
    else return;
    saveDraft(); rerender(myRecruiting);
  };
  el.onclick = (ev) => {
    const t = ev.target.closest("button");
    if (!t) return;
    if (t.dataset.move !== undefined) {
      const i = Number(t.dataset.move), j = i + Number(t.dataset.dir);
      [d.queue[i], d.queue[j]] = [d.queue[j], d.queue[i]];
    } else if (t.dataset.del !== undefined) d.queue.splice(Number(t.dataset.del), 1);
    else if (t.dataset.rm !== undefined) toggleBoard(Number(t.dataset.rm));
    else return;
    saveDraft(); rerender(myRecruiting);
  };
}

function gameHeader(n) {
  const c = n.card || {}, sc = n.scout;
  const facts = [];
  if (c.odds) facts.push(`<div><dt>Outlook</dt><dd><b>${esc(c.odds)}</b></dd></div>`);
  if (c.us) facts.push(`<div><dt>Us / them</dt><dd>${esc(c.us)} / ${esc(c.them)}</dd></div>`);
  if (c.oppRecord) facts.push(`<div><dt>Their record</dt><dd>${esc(c.oppRecord)}${c.oppRank ? ` · No. ${c.oppRank}` : ""}</dd></div>`);
  if (c.venue) facts.push(`<div><dt>Venue</dt><dd>${esc(c.venue)}${c.noise ? ` · ${esc(c.noise)}` : ""}</dd></div>`);
  if (c.kick) facts.push(`<div><dt>Kickoff</dt><dd>${esc(c.kick)}</dd></div>`);
  if (c.forecast) facts.push(`<div><dt>Forecast</dt><dd>${esc(c.forecast)}</dd></div>`);
  if (c.series) facts.push(`<div><dt>Series</dt><dd>${esc(c.series)}${c.lastMeeting ? ` · last: ${esc(c.lastMeeting)}` : ""}</dd></div>`);
  if (c.rivalry || c.trophy) facts.push(`<div><dt>Rivalry</dt><dd>${esc([c.rivalry, c.trophy].filter(Boolean).join(" · "))}</dd></div>`);
  return `<section class="panel"><h2>${esc(c.label || "Week " + n.week)}: ${n.site === "away" ? "at " : "vs "}<a href="#/team/${esc(n.oppId)}">${esc(n.opp)}</a></h2>
      <dl class="kv">${facts.join("")}</dl>
      ${n.film.length ? `<h3 style="margin-top:12px">From the film room</h3><ul>${n.film.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${sc ? `<h3 style="margin-top:12px">${esc(n.opp)} tendencies (${esc(sc.team)} team)</h3>
        <p><b>Offense</b> ${esc(sc.offense)}</p><p><b>Defense</b> ${esc(sc.defense)}</p>
        <p class="note">Staff says: ${esc(sc.tips.join("; "))}.</p>
        <h3 style="margin-top:12px">Their best players</h3>
        <div class="table-wrap"><table><tbody>${sc.best.map((b) => `<tr><td class="tight">${esc(b.p)}</td><td><b>${esc(b.n)}</b> <span class="quiet">${esc(b.yr)}</span><br><span class="quiet small">${esc(b.film)}</span></td><td>${esc(b.looks)}</td></tr>`).join("")}</tbody></table></div>` : ""}
    </section>`;
}

function myGameday(el) {
  const B = S.B, d = S.draft, G = B.gameday, R = S.rules;
  const openPlan = S.manifest.sections.includes("plan"), openDepth = S.manifest.sections.includes("depth"), openCalls = S.manifest.sections.includes("calls");
  const n = G.next;
  const keySel = (name, keys, cur, rec) => `<select id="${name}" ${openPlan ? "" : "disabled"}><option value="film" ${cur === "film" ? "selected" : ""}>The film's read${rec ? ` (${esc((keys[rec] || {}).label || rec)})` : ""}</option>
    ${Object.entries(keys).map(([k, v]) => `<option value="${k}" ${cur === k ? "selected" : ""}>${esc(v.label)}: ${esc(v.blurb)}</option>`).join("")}</select>`;
  const names = {};
  B.roster.forEach((p) => (names[p.id] = p));
  el.innerHTML = `
    ${n ? gameHeader(n) : `<div class="note">No game this week.</div>`}
    <div class="grid" style="margin-top:20px">
    <section><h2>Practice focus</h2><div class="choices">${[["staff", { label: "The staff's call", blurb: "weather prep when it's coming, balanced otherwise" }], ...Object.entries(R.focus)].map(([k, v]) => `<label class="choice ${d.plan.focus === k ? "on" : ""}"><input type="radio" name="focus" value="${k}" ${d.plan.focus === k ? "checked" : ""} ${openPlan ? "" : "disabled"}><span>${esc(v.label)}<small>${esc(v.blurb)}</small></span></label>`).join("")}</div></section>
    <section><h2>Game plan</h2>
      <div class="field"><label for="po">Offense</label>${keySel("po", R.offKeys, d.plan.off, n && n.recOff)}</div>
      <div class="field"><label for="pd">Defense</label>${keySel("pd", R.defKeys, d.plan.def, n && n.recDef)}</div>
      <label class="choice ${d.plan.script ? "on" : ""}"><input type="checkbox" id="ps" ${d.plan.script ? "checked" : ""} ${openPlan ? "" : "disabled"}><span>Script the openers<small>your first series follow the plan to the letter</small></span></label>
      <h2 style="margin-top:22px">Who calls plays</h2>
      <div class="field"><label for="co">Offense</label><select id="co" ${openCalls ? "" : "disabled"}><option value="HC" ${d.calls.off === "HC" ? "selected" : ""}>You</option>${G.oc ? `<option value="OC" ${d.calls.off === "OC" ? "selected" : ""}>Your OC, ${esc(G.oc)}</option>` : ""}</select></div>
      <div class="field"><label for="cd">Defense</label><select id="cd" ${openCalls ? "" : "disabled"}><option value="HC" ${d.calls.def === "HC" ? "selected" : ""}>You</option>${G.dc ? `<option value="DC" ${d.calls.def === "DC" ? "selected" : ""}>Your DC, ${esc(G.dc)}</option>` : ""}</select></div>
    </section></div>
    <section style="margin-top:28px"><h2>Depth chart</h2><p class="quiet">Leave a position with the staff and they re-sort it every week. Set your own order and it stays until you change it; injured players are skipped automatically.</p>
      <div class="grid">${R.positions.map((pos) => {
        const locked = d.locks[pos];
        const order = locked || G.depth[pos] || [];
        const starters = G.starters[pos] || 1;
        return `<div class="depth-pos"><h3>${pos} <span class="quiet">${locked ? "your order" : "staff decides"}</span></h3>
          ${openDepth ? `<button class="btn small ${locked ? "ghost" : ""}" data-lock="${pos}">${locked ? "Hand back to the staff" : "Set my own order"}</button>` : ""}
          <ol>${order.map((pid, i) => { const p = names[pid] || {}; return `<li class="${i < starters ? "starter" : ""}"><span class="n">${i + 1}</span><span class="grow">${esc(p.n || pid)} <span class="quiet">${esc(p.yr || "")} · ${esc(p.eval || "")}</span>${p.inj ? ` <span class="tag bad">${esc(p.inj)}</span>` : ""}</span>
            ${locked && openDepth ? `<button class="iconbtn" data-up="${pos}:${i}" ${i === 0 ? "disabled" : ""} aria-label="Move up">↑</button><button class="iconbtn" data-dn="${pos}:${i}" ${i === order.length - 1 ? "disabled" : ""} aria-label="Move down">↓</button>` : ""}</li>`; }).join("")}</ol></div>`;
      }).join("")}</div></section>`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.name === "focus") d.plan.focus = t.value;
    else if (t.id === "po") d.plan.off = t.value;
    else if (t.id === "pd") d.plan.def = t.value;
    else if (t.id === "ps") d.plan.script = t.checked;
    else if (t.id === "co") d.calls.off = t.value;
    else if (t.id === "cd") d.calls.def = t.value;
    else return;
    saveDraft(); rerender(myGameday);
  };
  el.onclick = (ev) => {
    const t = ev.target.closest("button");
    if (!t) return;
    if (t.dataset.lock) {
      const pos = t.dataset.lock;
      if (d.locks[pos]) delete d.locks[pos]; else d.locks[pos] = [...(G.depth[pos] || [])];
    } else if (t.dataset.up || t.dataset.dn) {
      const [pos, i0] = (t.dataset.up || t.dataset.dn).split(":"); const i = Number(i0), j = t.dataset.up ? i - 1 : i + 1;
      const o = d.locks[pos]; [o[i], o[j]] = [o[j], o[i]];
    } else return;
    saveDraft(); rerender(myGameday);
  };
}

const MOOD_TAG = { "fired up": "good", happy: "good", content: "", restless: "warn", unhappy: "bad", "wants out": "bad" };

function myRoster(el) {
  const B = S.B, groups = {};
  B.roster.forEach((p) => (groups[p.p] = groups[p.p] || []).push(p));
  const P = B.practice || { battles: [], ideas: [] };
  el.innerHTML = `<p class="muted">What your staff sees. No ratings: their read on each player, this week's practice and their notes. Open a name for his full card.</p>
    <div class="grid" style="margin-top:12px">
      <section><h2>Position battles</h2>${P.battles.length ? `<ul>${P.battles.map(([pos, t]) => `<li><b>${esc(pos)}</b> ${esc(t)}</li>`).join("")}</ul>` : `<p class="muted">No real battles this week. The depth chart is settled.</p>`}</section>
      <section><h2>Staff depth ideas</h2>${P.ideas.length ? `<ul>${P.ideas.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : `<p class="muted">The staff likes the depth chart as it is.</p>`}</section>
    </div>
    ${S.rules.positions.filter((pos) => groups[pos]).map((pos) => `<section><h2>${pos}</h2><div class="table-wrap"><table>
      <thead><tr><th class="tight">#</th><th>Name</th><th>Class</th><th>Looks like</th><th>Dev</th><th>Practice</th><th>Best at</th><th>Mood</th><th class="r">NIL</th></tr></thead><tbody>
      ${groups[pos].map((p) => `<tr class="${p.starter ? "starter-row" : ""}"><td class="num">${p.num}</td>
        <td><a href="#/my/player/${p.id}">${esc(p.n)}</a>${p.inj ? ` <span class="tag bad">${esc(p.inj)}</span>` : ""}${p.portal[0] ? ` <span class="tag warn">${esc(p.portal[0])}</span>` : ""}</td>
        <td>${esc(p.yr)}</td><td><b>${esc(p.eval)}</b> <span class="quiet">${esc(p.trend)}</span></td><td class="num">${esc(p.dev)}</td>
        <td class="quiet small">${esc(p.practice)}${p.week ? ` <span class="tag ${p.week === "good week" ? "good" : "bad"}">${esc(p.week)}</span>` : ""}</td>
        <td class="quiet">${esc(p.best.join(", "))}</td><td><span class="tag ${MOOD_TAG[p.mood] || ""}">${esc(p.mood)}</span></td>
        <td class="r num">${p.nil ? money(p.nil) : ""}</td></tr>`).join("")}</tbody></table></div></section>`).join("")}`;
}

function statTables(rows) {
  return rows.map(([g, cells]) => `<div class="statgrp"><h4>${esc(g)}</h4><dl>${cells.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl></div>`).join("");
}

async function viewMyPlayer(id) {
  if (!S.B) { location.hash = "#/login"; return; }
  const p = S.B.roster.find((x) => x.id === Number(id));
  if (!p) { app().innerHTML = `<p class="empty">He isn't on your roster.</p>`; return; }
  const st = p.staff || {};
  const kv = (k, v) => (v || v === 0 ? `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>` : "");
  app().innerHTML = `<p><a href="#/my/roster">Roster</a></p>
    <h1>#${p.num} ${esc(p.n)}</h1>
    <p class="muted">${esc(p.p)} · ${esc(p.yr)} · ${esc(p.ht)}, ${p.wt} lbs · ${esc(p.homeName || p.home)}${p.stars ? ` · ${stars(p.stars)} recruit` : ""}${p.transfer ? ` · transfer from ${esc(p.transfer)}` : ""}</p>
    ${p.gen ? `<div class="note good">Generational talent: the kind of prospect who comes along every few years.</div>` : ""}
    ${p.inj ? `<div class="note bad">${esc(p.inj)}</div>` : ""}
    <dl class="kv">
      ${kv("Looks like", `<b>${esc(p.eval)}</b>`)}${kv("Development", `<b>${esc(p.dev)}</b>`)}${kv("Ceiling", esc(p.potential))}
      ${kv("Durability", esc(p.durability.toLowerCase()))}${kv("Offseasons developed", p.developed)}${kv("Trend", esc(p.trend))}
      ${kv("Morale", `<b>${p.morale}</b> ${esc(p.mood)}`)}${kv("Classroom", esc(p.school))}${kv("NIL deal", p.nil ? money(p.nil) + " a year" : "none")}
      ${kv("Depth", `${p.depth} at ${esc(p.p)}${p.starter ? " (starter)" : ""}`)}${p.portal[0] ? kv("Transfer watch", `${esc(p.portal[0])}${p.portal[1] ? ` <span class="quiet">(${esc(p.portal[1])})</span>` : ""}`) : ""}
    </dl>
    ${p.lately.length ? `<p class="quiet">Lately: ${esc(p.lately.join("; "))}</p>` : ""}
    <div class="grid" style="margin-top:18px">
      <section class="panel"><h2>This week</h2>
        <p>${esc(p.practice || "No practice report yet.")}${p.week ? ` <span class="tag ${p.week === "good week" ? "good" : "bad"}">${esc(p.week)}</span>` : ""}</p>
        <p><b>Staff report:</b> ${esc(p.comments)}</p></section>
      <section class="panel"><h2>Depth room</h2>
        <dl class="kv">${kv("Staff board", st.board ? `${st.board}` : "")}${kv("Coordinator", st.coord ? `${st.coord}` : "")}${kv("Position coach", st.pos ? `${st.pos}` : "")}</dl>
        ${st.split ? `<p><span class="tag warn">Staff split</span></p>` : ""}
        ${st.coordNote ? `<p><b>Coordinator:</b> ${esc(st.coordNote)}</p>` : ""}${st.posNote ? `<p><b>Position coach:</b> ${esc(st.posNote)}</p>` : ""}
        <p class="quiet">${st.film && st.film.length ? `Film grades ${st.film.join(", ")} · ${esc(st.filmWord)}` : "No game film yet."}${st.camp && st.camp.length ? ` · Camp ${st.camp.map((v) => (v > 0 ? "+" : "") + v).join(", ")} (${esc(st.campWord)})` : ""}</p></section>
    </div>
    ${p.explain.length ? `<section style="margin-top:22px"><h2>Personality</h2><dl class="kv wide">${p.explain.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl></section>` : ""}
    <section style="margin-top:22px"><h2>${p.gp ? `${S.manifest.year} season · ${p.gp} game${p.gp === 1 ? "" : "s"}` : p.cgp ? `Career · ${p.cgp} games` : "Stats"}</h2>
      ${(p.season.length ? statTables(p.season) : p.career.length ? statTables(p.career) : `<p class="muted">No statistics recorded.</p>`)}
      ${p.gp && p.career.length ? `<h3 style="margin-top:12px">Career</h3>${statTables(p.career)}` : ""}</section>
    <section style="margin-top:22px"><h2>Game log</h2><div id="mylog"><p class="quiet">Loading…</p></div></section>
    <div class="grid" style="margin-top:22px">
      <section><h2>${esc(p.p)} skills</h2><table><tbody>${p.skills.map(([k, v]) => `<tr><td>${esc(k)}</td><td><b>${esc(v)}</b></td></tr>`).join("")}</tbody></table></section>
      <section><h2>Athlete</h2><table><tbody>${p.athlete.map(([k, v]) => `<tr><td>${esc(k)}</td><td><b>${esc(v)}</b></td></tr>`).join("")}</tbody></table>
        <h3 style="margin-top:14px">Other positions</h3><table><tbody>${p.alt.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</tbody></table></section>
    </div>
    ${p.timeline.length ? `<section style="margin-top:22px"><h2>Career timeline</h2>${p.timeline.map((y) => `<div class="tl"><b>${y.y}</b>${y.looked ? ` <span class="quiet">looked like: ${esc(y.looked)}</span>` : ""}
      ${y.events.length ? `<ul>${y.events.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}${y.stats ? `<p class="quiet">${esc(y.stats)}${y.gp ? ` (${y.gp} games)` : ""}</p>` : ""}</div>`).join("")}</section>` : ""}`;
  getJSON(`teams/${S.B.id}.json`).then((T) => {
    const pub = T.roster.find((x) => x.id === p.id);
    const el = $("#mylog");
    if (el) el.innerHTML = gameLog(pub && pub.log) + `<p class="quiet"><a href="#/player/${esc(S.B.id)}/${p.id}">What everyone else sees</a></p>`;
  }).catch(() => { const el = $("#mylog"); if (el) el.innerHTML = `<p class="muted">Game log unavailable.</p>`; });
}

function myCoach(el) {
  const c = S.B.coach || {}, card = S.B.card || {}, pg = S.B.program || {}, R = S.B.reports || {};
  const rep = (title, key) => (R[key] ? `<section style="margin-top:22px"><h2>${title}</h2><pre class="screen">${esc(R[key])}</pre></section>` : "");
  el.innerHTML = `<div class="grid">
    <section class="panel"><h2>${esc(c.name || "Head coach")}</h2>
      <p>Hot seat: <b>${esc(c.seatLabel || "")}</b> <span class="quiet">(${c.seat ?? ""}/100${c.seatMove ? `, ${c.seatMove > 0 ? "up" : "down"} ${Math.abs(c.seatMove)} this week` : ""})</span></p>
      ${c.contract ? `<p>Contract: ${esc(c.contract)}</p>` : ""}${c.ad ? `<p>Athletic director: ${esc(c.ad)}</p>` : ""}
      <p class="muted">${esc(card.record || "")} this season${card.confRecord ? `, ${esc(card.confRecord)} in conference` : ""}</p></section>
    <section><h2>Your AD's goals</h2>${(c.goals || []).length ? `<div class="table-wrap"><table><tbody>${c.goals.map((g) => `<tr><td>${esc(g.text)}</td><td><span class="tag ${g.status === "met" ? "good" : g.status === "failed" ? "bad" : ""}">${esc(g.status)}</span></td><td class="quiet">${esc(g.note)}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">No written goals. The mood is the bar.</p>`}</section>
    <section class="panel"><h2>Program</h2><dl class="kv">
      <div><dt>Prestige</dt><dd>${pg.prestige ?? ""}</dd></div><div><dt>Budget</dt><dd>${esc(pg.budget || "")}</dd></div>
      <div><dt>NIL free</dt><dd>${esc(pg.nil || "")}</dd></div><div><dt>Stadium</dt><dd>${(pg.capacity || 0).toLocaleString()} · ${esc(pg.noise || "")}</dd></div>
      ${(pg.facilities || []).map((f) => `<div><dt>${esc(f.k)} facilities</dt><dd>${f.v} of 10</dd></div>`).join("")}
      ${pg.project ? `<div><dt>Stadium project</dt><dd>${esc(pg.project)}</dd></div>` : ""}</dl></section>
    </div>
    ${rep("Program", "program")}${rep("Staff room", "staff")}${rep("Budget", "budget")}${rep("Facilities", "facilities")}${rep("Locker room", "locker")}${rep("Transfer watch", "portal")}`;
}

function viewGuide() {
  const R = S.rules, M = S.manifest;
  const off = (R.offseason || []).map((x, i) => `<li><b>${esc(x.label)}</b>${x.sections.length ? ` <span class="quiet">(you can send: ${esc(x.sections.join(", "))})</span>` : ""}</li>`).join("");
  app().innerHTML = `<h1>How the league works</h1><p class="muted">${esc(M.title)} · game build ${esc(M.gameBuild || "")}</p>
    <div class="grid" style="margin-top:16px">
    <section><h2>Each cycle</h2><ol>
      <li><b>Log in</b> with your program and the password the commissioner sent you. Your team's file opens in your browser; nothing is sent anywhere.</li>
      <li><b>Make your decisions</b> on the My team tabs. The strip at the top says what's open this cycle. Your draft is kept in this browser until the next cycle.</li>
      <li><b>Build your code</b> (My team → Code), copy it, and paste it in the submission form${M.formUrl ? ` (<a href="${esc(M.formUrl)}" target="_blank" rel="noopener">open it</a>)` : ""}. Only your newest code counts; build it again after any change.</li>
      <li>The commissioner imports every code, runs the cycle and posts the new site. What your staff learned shows up then.</li>
    </ol>
    <p class="quiet">Miss a cycle and your standing orders keep running: your recruiting queue, depth chart, game plan and play-calling stay as you left them. Miss two in a row and your staff also works a basic recruiting board. Five in a row and the commissioner is asked whether to open your program to someone else.</p></section>
    <section><h2>A season</h2><p>One cycle is one week: fall camp, Weeks 1-13, championship week, then the playoff and bowls. Then the offseason, in nine cycles:</p><ol>${off}</ol><p>Fall camp is next, and the new season begins.</p></section>
    <section><h2>What the words mean</h2><p class="quiet">You never see a player's rating. Your staff tells you what he looks like, on a fixed scale (lowest to highest):</p>
      <p><b>Players:</b> ${esc(R.scales.player.join(" · "))}</p>
      <p><b>Skills:</b> ${esc(R.scales.skill.join(" · "))}</p>
      <p><b>Athletic traits:</b> ${esc(R.scales.athlete.join(" · "))}</p>
      <p><b>Other teams:</b> ${esc(R.scales.team.join(" · "))}</p>
      <p class="quiet">Other programs' players show an approximate tier, re-read every four weeks. Recruit projections tighten as your staff evaluates him (scouted 0 to 3).</p></section>
    <section><h2>Recruiting hours</h2><p>Each week your staff has a set number of hours. Standing orders run top to bottom and anything that doesn't fit is cut; the bar at the bottom of the screen shows how your week fits. Actions: ${Object.values(R.actions).map((a) => `${esc(a.label)} (${a.cost}h)`).join(", ")}.</p>
      <p>Official visits cost ${R.ovCost}h (up to ${R.ovMax} per recruit, on a home game). Your board holds ${R.boardMax}.</p></section>
    <section><h2>Your job</h2><p>Your AD judges you like any head coach: wins against expectations, his goals, recruiting. Your hot seat is on the Program tab. ADs can fire you mid-season. Fired, you keep your coach and can be hired again; rank up to three jobs on the Jobs tab and the offseason market may call.</p></section>
    </div>`;
}

async function viewJobs() {
  const rows = await getJSON("jobs.json").catch(() => []);
  const sec = (kind) => rows.filter((r) => r.kind === kind);
  const table = (list) => `<div class="table-wrap"><table><thead><tr><th>Program</th><th class="r">Prestige</th><th>Roster</th><th>Situation</th>${S.B ? "<th>You</th>" : ""}</tr></thead><tbody>
    ${list.map((r) => `<tr><td>${teamLink(r.id)}${team(r.id).owner ? ` <span class="quiet">@${esc(team(r.id).owner)}</span>` : ""}</td><td class="r num">${r.prestige}</td><td>${esc(r.roster)}</td><td class="quiet">${esc(r.note)}</td>${S.B ? `<td>${esc(((S.B.jobs || {}).standing || {})[r.id] || "")}</td>` : ""}</tr>`).join("") || `<tr><td colspan="5" class="empty">None right now.</td></tr>`}</tbody></table></div>`;
  app().innerHTML = `<h1>Jobs</h1><p class="muted">Open head coaching jobs, and the seats closest to opening. ${S.B ? "Your standing is where you'd land on that AD's list. Rank up to three on My team → Jobs." : "Log in to see where you'd stand."}</p>
    <div class="grid" style="margin-top:18px"><section><h2>Open</h2>${table(sec("open"))}</section><section><h2>Could open</h2>${table(sec("could open"))}</section></div>`;
}

function myJobs(el) {
  const B = S.B, d = S.draft, J = B.jobs || {}, st = J.standing || {}, open = S.manifest.sections.includes("jobs");
  const ids = Object.keys(st);
  const opt = (cur) => `<option value="">none</option>${ids.map((id) => `<option value="${esc(id)}" ${cur === id ? "selected" : ""}>${esc(team(id).school)} (${esc(st[id])})</option>`).join("")}`;
  el.innerHTML = `<p class="muted">When the coaching market runs (in the offseason), any job you rank here can call you. The AD decides from where you'd stand on his list; if he offers, you've already said yes. A job you didn't rank goes to the commissioner to answer with you.</p>
    <section class="panel" style="margin-top:12px"><h2>Jobs you want</h2>
      <div class="controls">${[0, 1, 2].map((i) => `<label>${i + 1}. <select data-want="${i}" ${open ? "" : "disabled"}>${opt(d.jobs.want[i] || "")}</select></label>`).join("")}</div>
      <p class="quiet">Only open jobs and seats that could open are listed. See them all on the <a href="#/jobs">Jobs page</a>.</p>
      <h2 style="margin-top:16px">If your AD offers a new contract</h2>
      <div class="choices">${[["ask", "Let the commissioner ask me"], ["yes", "Sign it"], ["no", "Turn it down"]].map(([k, v]) => `<label class="choice ${d.jobs.extend === k ? "on" : ""}"><input type="radio" name="ext" value="${k}" ${d.jobs.extend === k ? "checked" : ""} ${open ? "" : "disabled"}><span>${v}</span></label>`).join("")}</div>
    </section>`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.dataset.want !== undefined) { d.jobs.want[Number(t.dataset.want)] = t.value; d.jobs.want = d.jobs.want.slice(0, 3); }
    else if (t.name === "ext") d.jobs.extend = t.value;
    else return;
    saveDraft(); rerender(myJobs);
  };
}

const CHAIRS = ["OC", "DC", "QB", "RB", "WR", "TE", "OL", "DL", "LB", "DB"];
const CHAIR_NAME = { OC: "Offensive coordinator", DC: "Defensive coordinator", QB: "Quarterbacks", RB: "Running backs", WR: "Wide receivers", TE: "Tight ends", OL: "Offensive line", DL: "Defensive line", LB: "Linebackers", DB: "Defensive backs" };

function myStaff(el) {
  const B = S.B, d = S.draft, ST = B.staff || {}, open = S.manifest.sections.includes("staff"), off = S.manifest.sections.includes("nil");
  const chair = d._chair || "OC";
  const isCoord = chair === "OC" || chair === "DC";
  const L = d.staff.lists[chair] = d.staff.lists[chair] || (isCoord ? { names: [], max: { salary: Math.round(ST.std.coord * 1.2), years: 3, calls: 0, title: 0, out: 0 } } : { names: [], premium: 0 });
  const market = (ST.markets || {})[chair] || [];
  el.innerHTML = `<p class="muted">Your staff, and the lists your AD works from if a chair opens this winter (a coach leaves, retires, or you let him go). He calls your names in order with your best package; if nobody says yes, he makes the hire.</p>
    <div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Chair</th><th>Coach</th><th class="r">Age</th><th class="r">OVR</th><th>Notes</th><th class="r">Pay</th>${off ? "<th>Let go</th>" : ""}</tr></thead><tbody>
    ${(ST.now || []).map((c) => `<tr><td>${esc(CHAIR_NAME[c.key])}</td><td>${c.name ? esc(c.name) : `<span class="tag bad">open</span>`}</td><td class="r num">${c.age ?? ""}</td><td class="r num">${c.cov ?? ""}</td>
      <td class="quiet">${esc([c.pot, c.calls ? "calls plays" : "", c.kind, c.spec, c.dev ? `DEV ${c.dev} · REC ${c.rec}` : ""].filter(Boolean).join(" · "))}</td><td class="r num">${c.pay ? money(c.pay) : ""}</td>
      ${off ? `<td>${c.name ? `<input type="checkbox" data-fire="${c.key}" ${d.staff.fire.includes(c.key) ? "checked" : ""} ${open ? "" : "disabled"}>` : ""}</td>` : ""}</tr>`).join("")}</tbody></table></div>
    ${!off ? `<p class="quiet">Letting a coach go opens in the offseason.</p>` : ""}
    ${ST.report && ST.report.length ? `<section style="margin-top:18px"><h2>What happened</h2><ul>${ST.report.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></section>` : ""}
    <section style="margin-top:22px"><h2>If a chair opens</h2>
      <div class="weekpick">${CHAIRS.map((k) => `<a class="chip ${k === chair ? "on" : ""}" href="javascript:void 0" data-chair="${k}">${k}${(d.staff.lists[k] || {}).names && d.staff.lists[k].names.length ? ` (${d.staff.lists[k].names.length})` : ""}</a>`).join("")}</div>
      <div class="grid">
        <section class="panel"><h3>Your list for ${esc(CHAIR_NAME[chair])}</h3>
          ${L.names.length ? `<ol>${L.names.map((n, i) => `<li>${esc(n)} <button class="iconbtn" data-up="${i}" ${i === 0 ? "disabled" : ""}>↑</button><button class="iconbtn" data-rm="${i}">✕</button></li>`).join("")}</ol>` : `<p class="muted">Empty: the AD would hire on his own.</p>`}
          ${isCoord ? `<h3 style="margin-top:10px">Your best package</h3><div class="controls">
            <label>Up to $/yr <input type="number" step="50000" min="0" data-max="salary" value="${L.max.salary}"></label>
            <label>Years <input type="number" min="1" max="6" data-max="years" value="${L.max.years}" style="width:64px"></label>
            <label><input type="checkbox" data-max="calls" ${L.max.calls ? "checked" : ""}> He can call plays</label>
            <label><input type="checkbox" data-max="title" ${L.max.title ? "checked" : ""}> Assistant head coach title</label>
            <label><input type="checkbox" data-max="out" ${L.max.out ? "checked" : ""}> Head-job out-clause</label></div>
            <p class="quiet">Standard coordinator pay here: ${money(ST.std.coord)}.</p>`
            : `<div class="controls"><label>Pay up to <select data-prem="1">${[0, 15, 30].map((v) => `<option value="${v}" ${L.premium === v ? "selected" : ""}>${v ? v + "% over standard" : "standard"}</option>`).join("")}</select></label></div><p class="quiet">Standard position coach pay here: ${money(ST.std.pos)}.</p>`}
        </section>
        <section class="wide"><h3>On the market</h3><p class="quiet">What your staff knows before anyone calls: public buzz, the résumé and the ratings the game shows for coaches.</p>
          <div class="table-wrap"><table><thead><tr><th>Coach</th><th class="r">Age</th><th class="r">OVR</th>${isCoord ? `<th class="r">Side</th><th class="r">REC</th>` : `<th class="r">DEV</th><th class="r">REC</th>`}<th>Now</th><th>Buzz</th><th></th></tr></thead><tbody>
          ${market.map((c) => `<tr><td>${c.tie ? "★ " : ""}${esc(c.name)}<br><span class="quiet small">${esc([c.pers, c.pot, c.calls ? "calls plays" : "", c.unit, c.kind, c.spec].filter(Boolean).join(" · "))}</span></td><td class="r num">${c.age}</td><td class="r num">${c.cov}</td>
            ${isCoord ? `<td class="r num">${c.side}</td><td class="r num">${c.rec}</td>` : `<td class="r num">${c.dev}</td><td class="r num">${c.rec}</td>`}<td class="quiet small">${esc(c.now)}</td><td>${esc(c.buzz)}</td>
            <td>${open && !L.names.includes(c.name) && L.names.length < 10 ? `<button class="btn small" data-add="${esc(c.name)}">Add</button>` : ""}</td></tr>`).join("") || `<tr><td colspan="8" class="empty">Nobody on the market for this chair.</td></tr>`}</tbody></table></div>
        </section></div></section>`;
  el.onclick = (ev) => {
    const t = ev.target.closest("[data-chair],[data-add],[data-up],[data-rm]");
    if (!t) return;
    if (t.dataset.chair) d._chair = t.dataset.chair;
    else if (t.dataset.add) L.names.push(t.dataset.add);
    else if (t.dataset.up) { const i = Number(t.dataset.up); [L.names[i - 1], L.names[i]] = [L.names[i], L.names[i - 1]]; }
    else if (t.dataset.rm) L.names.splice(Number(t.dataset.rm), 1);
    saveDraft(); rerender(myStaff);
  };
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.dataset.fire) { d.staff.fire = d.staff.fire.filter((x) => x !== t.dataset.fire); if (t.checked) d.staff.fire.push(t.dataset.fire); }
    else if (t.dataset.max) L.max[t.dataset.max] = t.type === "checkbox" ? (t.checked ? 1 : 0) : Number(t.value || 0);
    else if (t.dataset.prem) L.premium = Number(t.value);
    else return;
    saveDraft();
  };
}

function myMoney(el) {
  const B = S.B, d = S.draft, M = B.money || {}, m = d.money, open = S.manifest.sections.includes("money");
  const name = (pid) => (B.roster.find((p) => p.id === pid) || {}).n || `#${pid}`;
  const tog = (arr, v, on) => { const i = arr.indexOf(v); if (on && i < 0) arr.push(v); if (!on && i >= 0) arr.splice(i, 1); };
  el.innerHTML = `<p class="muted">Your budget is ${money(M.budget || 0)}; ${money(M.free || 0)} is free for NIL right now. Each ask below gets the same answer odds as in Coach Career, once a year per person. See the full budget on the Program tab.</p>
    <div class="grid" style="margin-top:12px">
    <section class="panel"><h2>Facilities</h2>${Object.entries(M.facilities || {}).map(([k, f]) => `<label class="choice ${m.facility === k ? "on" : ""}"><input type="radio" name="fac" value="${k}" ${m.facility === k ? "checked" : ""} ${open && f.ok ? "" : "disabled"}><span>${k === "recruiting" ? "Recruiting" : "Training"} facilities: level ${f.level} of 10<small>${f.ok ? `upgrade for ${money(f.cost)}` : esc(f.why)}</small></span></label>`).join("")}
      <label class="choice ${!m.facility ? "on" : ""}"><input type="radio" name="fac" value="" ${!m.facility ? "checked" : ""} ${open ? "" : "disabled"}><span>No project this time</span></label></section>
    <section class="panel"><h2>Find the money</h2>
      <h3>Ask a player to take 25% less NIL</h3>${(M.deals || []).map(([pid, amt, asked]) => `<label><input type="checkbox" data-rs="${pid}" ${m.restructure.includes(pid) ? "checked" : ""} ${open && !asked ? "" : "disabled"}> ${esc(name(pid))} · ${money(amt)}/yr${asked ? " (asked this year)" : ""}</label><br>`).join("") || `<p class="muted">No deals count against next season.</p>`}
      <h3 style="margin-top:10px">Ask a coordinator for 15% less</h3>${(M.coords || []).map(([r, n, sal, asked]) => `<label><input type="checkbox" data-cc="${r}" ${m.coordcut.includes(r) ? "checked" : ""} ${open && !asked ? "" : "disabled"}> ${r} ${esc(n)} · ${money(sal)}/yr</label><br>`).join("")}
      <h3 style="margin-top:10px">Ask a position coach for 10% less</h3>${(M.pos || []).map(([g, n, sal, asked]) => `<label><input type="checkbox" data-pc="${g}" ${m.poscut.includes(g) ? "checked" : ""} ${open && !asked ? "" : "disabled"}> ${g} ${esc(n)} · ${money(sal)}</label>`).join(" ")}
      ${(M.buyouts || []).length ? `<h3 style="margin-top:10px">Buyouts due next season</h3><ul>${M.buyouts.map(([n, amt, st]) => `<li>${esc(n)} · ${money(amt)}${st ? " (stretched)" : ""}</li>`).join("")}</ul><label><input type="checkbox" id="stretch" ${m.stretch ? "checked" : ""} ${open ? "" : "disabled"}> Ask to spread them over three years (10% more in all)</label>` : ""}
    </section></div>`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.name === "fac") m.facility = t.value;
    else if (t.dataset.rs) tog(m.restructure, Number(t.dataset.rs), t.checked);
    else if (t.dataset.cc) tog(m.coordcut, t.dataset.cc, t.checked);
    else if (t.dataset.pc) tog(m.poscut, t.dataset.pc, t.checked);
    else if (t.id === "stretch") m.stretch = t.checked;
    else return;
    saveDraft(); rerender(myMoney);
  };
}

function mySeason(el) {
  const B = S.B, d = S.draft, E = B.seasonEnd || { nil: [], draft: [] }, open = S.manifest.sections.includes("nil");
  const P = (pid) => B.roster.find((p) => p.id === pid) || {};
  el.innerHTML = `<p class="muted">After the title game: players asking for NIL raises, and juniors deciding about the draft. Leave one blank and your staff handles it the way any program's staff would.</p>
    <section style="margin-top:12px"><h2>NIL raises</h2><p class="quiet">Room in next year's NIL pool: ${money(E.room || 0)}.</p>
    ${E.nil.length ? `<div class="table-wrap"><table><thead><tr><th>Player</th><th class="r">Now</th><th class="r">Asks</th><th>Staff would</th><th>Your answer</th></tr></thead><tbody>${E.nil.map((x) => { const p = P(x.id); return `<tr><td><a href="#/my/player/${x.id}">${esc(p.n)}</a> <span class="quiet">${esc(p.p)} ${esc(p.yr)} · ${esc(p.eval)}</span>${x.threat ? ` <span class="tag bad">portal threat</span>` : ""}</td>
      <td class="r num">${money(x.was)}</td><td class="r num">${money(x.ask)}</td><td class="quiet">${x.staff}</td>
      <td><select data-nil="${x.id}" ${open ? "" : "disabled"}><option value="">Staff decides</option><option value="pay" ${d.nilAns[x.id] === "pay" ? "selected" : ""}>Pay ${money(x.ask)}</option><option value="counter" ${d.nilAns[x.id] === "counter" ? "selected" : ""}>Counter at ${money(x.counter)}</option><option value="refuse" ${d.nilAns[x.id] === "refuse" ? "selected" : ""}>Refuse</option></select></td></tr>`; }).join("")}</tbody></table></div>` : `<p class="muted">Nobody is asking for a raise.</p>`}</section>
    <section style="margin-top:22px"><h2>The draft</h2>
    ${E.draft.length ? `<div class="table-wrap"><table><thead><tr><th>Player</th><th>Projected</th><th>What you tell him</th></tr></thead><tbody>${E.draft.map((x) => { const p = P(x.id); return `<tr><td><a href="#/my/player/${x.id}">${esc(p.n)}</a> <span class="quiet">${esc(p.p)} ${esc(p.yr)} · ${esc(p.eval)}</span></td><td>round ${x.round}</td>
      <td><select data-draft="${x.id}" ${open ? "" : "disabled"}><option value="">Nothing yet</option><option value="stay" ${d.draftAns[x.id] === "stay" ? "selected" : ""}>Come back for another year</option><option value="go" ${d.draftAns[x.id] === "go" ? "selected" : ""}>Go: you're ready</option><option value="neutral" ${d.draftAns[x.id] === "neutral" ? "selected" : ""}>Your call, we support you</option></select></td></tr>`; }).join("")}</tbody></table></div><p class="quiet">It's his decision in the end: what you tell him moves the odds.</p>` : `<p class="muted">Nobody is draft-eligible with a real projection.</p>`}</section>`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.dataset.nil) { if (t.value) d.nilAns[t.dataset.nil] = t.value; else delete d.nilAns[t.dataset.nil]; }
    else if (t.dataset.draft) { if (t.value) d.draftAns[t.dataset.draft] = t.value; else delete d.draftAns[t.dataset.draft]; }
    else return;
    saveDraft();
  };
}

function myPortal(el) {
  const B = S.B, d = S.draft, P = B.portal || {}, open = S.manifest.sections.includes("portal");
  const pos = d._ppos || "";
  const board = (P.board || []).filter((x) => !pos || x.p === pos);
  el.innerHTML = `<p class="muted">Portal Window I. Talk to your own players who entered (a raise helps), and offer spots to anyone on the board. If you send nothing here, your staff works the portal for you.${P.room !== undefined ? ` NIL room for transfers: <b>${money(P.room)}</b>.` : ""}</p>
    <section style="margin-top:12px"><h2>Leaving you</h2>${(P.mine || []).length ? `<div class="table-wrap"><table><thead><tr><th>Player</th><th>Looks like</th><th>Why</th><th class="r">NIL was</th><th>Keep him</th></tr></thead><tbody>
      ${P.mine.map((x) => `<tr><td>${esc(x.n)} <span class="quiet">${esc(x.p)} ${esc(x.yr)}</span></td><td>${esc(x.looks)}</td><td class="quiet">${esc(x.why)}</td><td class="r num">${x.nil ? money(x.nil) : ""}</td>
        <td>${x.dest ? `gone to ${teamLink(x.dest)}` : `<label><input type="checkbox" data-keep="${x.id}" ${d.keep[x.id] !== undefined ? "checked" : ""} ${open ? "" : "disabled"}> talk to him</label> <label>raise $<input type="number" step="5000" min="0" data-raise="${x.id}" value="${d.keep[x.id] || 0}" style="width:110px" ${open ? "" : "disabled"}></label>`}</td></tr>`).join("")}</tbody></table></div>` : `<p class="muted">Nobody from your roster entered.</p>`}</section>
    <section style="margin-top:22px"><h2>The board</h2>
      <div class="controls"><select id="ppos"><option value="">All positions</option>${S.rules.positions.map((p) => `<option ${p === pos ? "selected" : ""}>${p}</option>`).join("")}</select>
        <span class="quiet">${Object.keys(d.poffer).length} of 8 offers</span></div>
      <div class="table-wrap"><table><thead><tr><th>Player</th><th>Looks like (approx.)</th><th>From</th><th>Why he left</th><th>Offer</th></tr></thead><tbody>
      ${board.slice(0, 150).map((x) => `<tr><td>${esc(x.n)} <span class="quiet">${esc(x.p)} ${esc(x.yr)}</span>${x.stars ? ` ${stars(x.stars)}` : ""}</td><td>${esc(x.looks)}</td><td>${teamLink(x.from)}</td><td class="quiet">${esc(x.why)}</td>
        <td>${x.dest ? `to ${teamLink(x.dest)}` : `<label><input type="checkbox" data-poff="${x.id}" ${d.poffer[x.id] !== undefined ? "checked" : ""} ${open ? "" : "disabled"}> offer</label> <label>NIL $<input type="number" step="5000" min="0" data-pnil="${x.id}" value="${d.poffer[x.id] || 0}" style="width:110px" ${open ? "" : "disabled"}></label>`}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">Nobody here.</td></tr>`}</tbody></table></div></section>`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.id === "ppos") { d._ppos = t.value; saveDraft(); rerender(myPortal); return; }
    if (t.dataset.keep) { if (t.checked) d.keep[t.dataset.keep] = d.keep[t.dataset.keep] || 0; else delete d.keep[t.dataset.keep]; }
    else if (t.dataset.raise) { d.keep[t.dataset.raise] = Number(t.value || 0); }
    else if (t.dataset.poff) { if (t.checked && Object.keys(d.poffer).length < 8) d.poffer[t.dataset.poff] = d.poffer[t.dataset.poff] || 0; else delete d.poffer[t.dataset.poff]; }
    else if (t.dataset.pnil) { if (d.poffer[t.dataset.pnil] !== undefined) d.poffer[t.dataset.pnil] = Number(t.value || 0); }
    else return;
    saveDraft(); rerender(myPortal);
  };
}

function myRosterWeek(el) {
  const B = S.B, d = S.draft, R = B.rosterWeek || {}, open = S.manifest.sections.includes("roster");
  const ideas = {};
  (R.ideas || []).forEach(([pid, from, to, why]) => (ideas[pid] = [to, why]));
  const groups = {};
  B.roster.forEach((p) => (groups[p.p] = groups[p.p] || []).push(p));
  el.innerHTML = `<p class="muted">The new class is on campus. Move players to new positions and cut anyone you don't want to carry. When the cycle runs, every room is trimmed to its size (lowest first, walk-ons before scholarship players) and filled with walk-ons where short.</p>
    ${S.rules.positions.filter((pos) => groups[pos]).map((pos) => { const cnt = (R.count || {})[pos] || 0, size = (R.size || {})[pos] || 0; return `<section><h2>${pos} <span class="quiet">${cnt} of ${size}${cnt > size ? `, ${cnt - size} over` : ""}</span></h2><div class="table-wrap"><table><tbody>
      ${groups[pos].map((p) => `<tr><td>${esc(p.n)} <span class="quiet">${esc(p.yr)}</span></td><td>${esc(p.eval)}</td><td class="quiet">${ideas[p.id] ? `staff idea: ${esc(ideas[p.id][0])} (${esc(ideas[p.id][1])})` : ""}</td>
        <td><select data-move="${p.id}" ${open ? "" : "disabled"}><option value="">stay at ${pos}</option>${S.rules.positions.filter((x) => x !== pos).map((x) => `<option ${d.moves[p.id] === x ? "selected" : ""}>${x}</option>`).join("")}</select></td>
        <td><label><input type="checkbox" data-cut="${p.id}" ${d.cuts.includes(p.id) ? "checked" : ""} ${open ? "" : "disabled"}> cut</label></td></tr>`).join("")}</tbody></table></div></section>`; }).join("")}`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.dataset.move) { if (t.value) d.moves[t.dataset.move] = t.value; else delete d.moves[t.dataset.move]; }
    else if (t.dataset.cut) { const id = Number(t.dataset.cut); d.cuts = d.cuts.filter((x) => x !== id); if (t.checked) d.cuts.push(id); }
    else return;
    saveDraft();
  };
}

const EMPH = { fundamentals: ["Fundamentals", "Young players develop faster; cleaner technique, lower volatility."], competition: ["Competition", "More live reps; sharper evaluations and more depth-chart movement."],
  young: ["Young players", "Freshmen and sophomores get extra reps and development."], physical: ["Physicality", "OL/DL/LB/RB extra work; more development, a little more injury risk."],
  chemistry: ["Chemistry", "Leadership and team work; morale rises and the room settles."], passing: ["Passing game", "QB/WR/TE/CB/S get extra competitive reps."] };

function mySpring(el) {
  const B = S.B, d = S.draft, open = S.manifest.sections.includes("spring"), R = B.spring;
  el.innerHTML = `${open ? `<section class="panel"><h2>Spring plan</h2><div class="choices">${Object.entries(EMPH).map(([k, [l, b]]) => `<label class="choice ${d.spring.emphasis === k ? "on" : ""}"><input type="radio" name="emph" value="${k}" ${d.spring.emphasis === k ? "checked" : ""}><span>${l}<small>${b}</small></span></label>`).join("")}</div>
      <h3 style="margin-top:12px">Position battles to watch (up to 3)</h3><div class="controls">${S.rules.positions.map((p) => `<label><input type="checkbox" data-focus="${p}" ${d.spring.focus.includes(p) ? "checked" : ""}> ${p}</label>`).join("")}</div></section>` : ""}
    ${R ? `<section style="margin-top:20px"><h2>Spring ${R.year}: ${esc((EMPH[R.emphasis] || [R.emphasis])[0])}</h2>
      <p>A-Day: <b>${esc((R.aday || {}).score || "")}</b></p>
      <div class="grid"><section><h3>Stock up</h3><ul>${(R.stock_up || []).map((x) => `<li>${esc(x)}</li>`).join("") || "<li class='quiet'>Nobody stood out.</li>"}</ul></section>
      <section><h3>Stock down</h3><ul>${(R.stock_down || []).map((x) => `<li>${esc(x)}</li>`).join("") || "<li class='quiet'>Nobody slipped.</li>"}</ul></section>
      <section><h3>A-Day film</h3><ul>${((R.aday || {}).film || []).slice(0, 8).map(([n, p, sc]) => `<li>${esc(p)} ${esc(n)} <span class="quiet">${sc > 0 ? "+" : ""}${sc}</span></li>`).join("")}</ul></section>
      ${(R.injuries || []).length ? `<section><h3>Medical</h3><ul>${R.injuries.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></section>` : ""}</div></section>` : ""}`;
  el.onchange = (ev) => {
    const t = ev.target;
    if (t.name === "emph") d.spring.emphasis = t.value;
    else if (t.dataset.focus) { d.spring.focus = d.spring.focus.filter((x) => x !== t.dataset.focus); if (t.checked && d.spring.focus.length < 3) d.spring.focus.push(t.dataset.focus); }
    else return;
    saveDraft(); rerender(mySpring);
  };
}

function buildOrders() {
  const B = S.B, d = S.draft, secs = S.manifest.sections, o = {};
  if (secs.includes("rec")) {
    const before = new Set(B.recruiting.board), after = new Set(d.board);
    const rec = {
      add: d.board.filter((x) => !before.has(x)), drop: B.recruiting.board.filter((x) => !after.has(x)),
      q: d.queue.map((e) => [e.rid, e.act, e.rule, e.rule === "weeks" ? (e.n || 1) : 0, e.pitch || "auto"]),
      auto: { OC: [d.auto.OC[0] ? 1 : 0, d.auto.OC[1]], DC: [d.auto.DC[0] ? 1 : 0, d.auto.DC[1]] },
    };
    const ov = Object.entries(d.ov).map(([k, v]) => [Number(k), Number(v)]);
    const nil = Object.entries(d.nil).map(([k, v]) => [Number(k), Number(v)]);
    const prom = Object.entries(d.prom).map(([k, v]) => [Number(k), v]);
    if (ov.length) rec.ov = ov;
    if (nil.length) rec.nil = nil;
    if (prom.length) rec.prom = prom;
    if (d.pwo.length) rec.pwo = d.pwo;
    o.rec = rec;
  }
  if (secs.includes("depth")) {
    const dep = {};
    Object.entries(d.locks).forEach(([pos, ids]) => (dep[pos] = ids));
    Object.keys(B.gameday.locks || {}).forEach((pos) => { if (!d.locks[pos]) dep[pos] = "staff"; });
    if (Object.keys(dep).length) o.depth = dep;
  }
  if (secs.includes("plan")) o.plan = { focus: d.plan.focus, off: d.plan.off, def: d.plan.def, script: d.plan.script ? 1 : 0 };
  if (secs.includes("calls")) o.calls = { off: d.calls.off, def: d.calls.def };
  if (secs.includes("staff") && d.staff) {
    const lists = {};
    Object.entries(d.staff.lists).forEach(([k, v]) => { if (v && v.names && v.names.length) lists[k] = v; });
    if (d.staff.fire.length || Object.keys(lists).length) o.staff = { fire: d.staff.fire, lists };
  }
  if (secs.includes("money") && d.money) {
    const m = d.money;
    if (m.facility || m.restructure.length || m.coordcut.length || m.poscut.length || m.stretch) o.money = m;
  }
  if (secs.includes("nil") && (Object.keys(d.nilAns).length || Object.keys(d.draftAns).length)) {
    o.nil = { nil: Object.entries(d.nilAns).map(([k, v]) => [Number(k), v]), draft: Object.entries(d.draftAns).map(([k, v]) => [Number(k), v]) };
  }
  if (secs.includes("portal") && (Object.keys(d.keep).length || Object.keys(d.poffer).length)) {
    o.portal = { keep: Object.entries(d.keep).map(([k, v]) => [Number(k), Number(v) || 0]), offer: Object.entries(d.poffer).map(([k, v]) => [Number(k), Number(v) || 0]) };
  }
  if (secs.includes("roster") && (Object.keys(d.moves).length || d.cuts.length)) o.roster = { move: Object.entries(d.moves).map(([k, v]) => [Number(k), v]), cut: d.cuts };
  if (secs.includes("spring")) o.spring = { emphasis: d.spring.emphasis, focus: d.spring.focus };
  if (secs.includes("jobs") && d.jobs) o.jobs = { want: [...new Set(d.jobs.want.filter(Boolean))].slice(0, 3), extend: d.jobs.extend || "ask" };
  return o;
}

function myCode(el) {
  const d = S.draft, B = S.B, p = planHours(), o = buildOrders();
  const cut = p.rows.filter((r) => r.status.startsWith("cut")).length;
  const lines = [];
  if (o.rec) {
    lines.push(`${o.rec.q.length} standing orders, ${p.used} of ${p.avail} hours planned`);
    if (o.rec.add.length || o.rec.drop.length) lines.push(`Board: ${o.rec.add.length} added, ${o.rec.drop.length} removed`);
    ["ov", "nil", "prom", "pwo"].forEach((k) => o.rec[k] && lines.push(`${{ ov: "Official visits", nil: "NIL offers", prom: "Promises", pwo: "Walk-on invites" }[k]}: ${o.rec[k].length}`));
  }
  if (o.plan) lines.push(`Practice: ${o.plan.focus === "staff" ? "the staff's call" : S.rules.focus[o.plan.focus].label}; offense: ${o.plan.off === "film" ? "the film's read" : S.rules.offKeys[o.plan.off].label}; defense: ${o.plan.def === "film" ? "the film's read" : S.rules.defKeys[o.plan.def].label}`);
  if (o.staff) lines.push(`Staff: ${o.staff.fire.length ? "let go " + o.staff.fire.join(", ") + "; " : ""}lists for ${Object.keys(o.staff.lists).join(", ") || "no chairs"}`);
  if (o.money) lines.push(`Money: ${[o.money.facility && o.money.facility + " facilities", o.money.restructure.length && o.money.restructure.length + " NIL restructures", o.money.coordcut.length && "coordinator pay cuts", o.money.poscut.length && "position coach pay cuts", o.money.stretch && "stretch buyouts"].filter(Boolean).join(", ")}`);
  if (o.nil) lines.push(`Season end: ${o.nil.nil.length} NIL answers, ${o.nil.draft.length} draft talks`);
  if (o.portal) lines.push(`Portal: ${o.portal.keep.length} retention talks, ${o.portal.offer.length} offers`);
  if (o.roster) lines.push(`Roster week: ${o.roster.move.length} position changes, ${o.roster.cut.length} cuts`);
  if (o.spring) lines.push(`Spring: ${(EMPH[o.spring.emphasis] || [o.spring.emphasis])[0]}${o.spring.focus.length ? ", watching " + o.spring.focus.join(", ") : ""}`);
  if (o.jobs) lines.push(`Jobs: ${o.jobs.want.length ? o.jobs.want.map((id) => team(id).school).join(", ") : "not looking"}; extension offers: ${{ ask: "ask me", yes: "sign", no: "turn down" }[o.jobs.extend]}`);
  if (o.calls) lines.push(`Play-calling: offense ${o.calls.off === "HC" ? "you" : "your OC"}, defense ${o.calls.def === "HC" ? "you" : "your DC"}`);
  if (o.depth) lines.push(`Depth chart: ${Object.entries(o.depth).map(([k, v]) => `${k} ${v === "staff" ? "back to the staff" : "your order"}`).join(", ")}`);
  el.innerHTML = `<section class="panel"><h2>Cycle ${B.cycle} orders</h2>
    ${Object.keys(o).length ? `<ul>${lines.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : `<p class="muted">No orders are open this cycle.</p>`}
    ${cut ? `<div class="note">${cut} standing order${cut === 1 ? "" : "s"} won't fit in this week's hours and will be cut. Reorder or remove some, or keep them for next week.</div>` : ""}
    ${d.board.length > S.rules.boardMax ? `<div class="note bad">Your board is over ${S.rules.boardMax}.</div>` : ""}
    <div class="controls" style="margin-top:12px"><button class="btn go" id="build" ${Object.keys(o).length ? "" : "disabled"}>Build my code</button>
      <button class="btn ghost" id="reset">Start over from last cycle's orders</button></div>
    <div id="out" class="codebox"></div></section>
    <p class="quiet" style="margin-top:14px">Your code is signed with your team's key. Build it again after any change: only the newest code you submit counts.</p>`;
  $("#build").onclick = async () => {
    try {
      const code = await signCode(B, o);
      $("#out").innerHTML = `<label for="code" class="quiet">Your code (${code.length} characters)</label><textarea id="code" rows="6" readonly>${esc(code)}</textarea>
        <div class="controls" style="margin-top:8px"><button class="btn go" id="copy">Copy code</button>${S.manifest.formUrl ? `<a class="btn" href="${esc(S.manifest.formUrl)}" target="_blank" rel="noopener">Open the submission form</a>` : `<span class="quiet">Paste it where the commissioner asked.</span>`}</div>`;
      $("#copy").onclick = async () => {
        const ta = $("#code");
        try { await navigator.clipboard.writeText(ta.value); } catch (e) { ta.select(); document.execCommand("copy"); }
        $("#copy").textContent = "Copied";
      };
    } catch (e) { $("#out").innerHTML = `<div class="note bad">${esc(e.message)}</div>`; }
  };
  $("#reset").onclick = () => {
    if (!confirm("Throw away this cycle's changes and start from the orders already in force?")) return;
    S.draft = freshDraft(B); saveDraft(); viewMy("code");
  };
}

// ═══ Start ═════════════════════════════════════════════════════════════════

async function start() {
  const theme = store.get("cc-theme");
  if (theme) document.documentElement.dataset.theme = theme;
  try {
    const r = await fetch(`data/manifest.json?t=${Date.now()}`);
    if (!r.ok) throw new Error("The league data isn't here yet. Ask the commissioner to export the site.");
    S.manifest = await r.json();
    S.rules = await getJSON("rules.json");
  } catch (e) { app().innerHTML = `<div class="note bad">${esc(e.message)}</div>`; return; }
  S.manifest.teams.forEach((t) => (S.teamById[t.id] = t));
  document.title = S.manifest.title;
  $("#league-title").textContent = S.manifest.title;
  $("#foot").textContent = `${S.manifest.title} · cycle ${S.manifest.cycle} · league ${S.manifest.league}`;
  renderStrip();
  const saved = sess.get("cc-login");
  if (saved) { try { await login(saved.id, saved.pw); } catch (e) { sess.del("cc-login"); } }
  renderWho();
  window.addEventListener("hashchange", route);
  route();
}
start();

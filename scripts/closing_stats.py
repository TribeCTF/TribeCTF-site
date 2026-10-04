#!/usr/bin/env python3
"""TribeCTF closing-ceremony stats from a CTFd backup zip.

Usage:
    python3 scripts/closing_stats.py [path/to/export.zip] [--no-deck]

- Picks the latest archive/*.zip by the UTC timestamp in its name unless a path is given.
- Reads db/*.json straight from the zip (read-only, in memory). Never writes PII.
- Writes closing-2026-slides/stats.json and rewrites the inline
  <script id="stats" type="application/json"> block in closing-2026-slides/index.html.
- Funny flags shown on the deck come from closing-2026-slides/funny_flags.txt
  (one flag per line, '#' comments allowed). Candidates are printed below; you pick.

Stdlib only.
"""
import datetime as dt
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ARCHIVE = REPO / "archive"
DECK_DIR = REPO / "closing-2026-slides"
DECK = DECK_DIR / "index.html"
STATS_JSON = DECK_DIR / "stats.json"
FUNNY = DECK_DIR / "funny_flags.txt"

ELIGIBLE_MIN = 2000
PRIZES = ["$2,500", "$1,000", "$500"]
EDT = dt.timezone(dt.timedelta(hours=-4), "EDT")

# Difficulty is not tagged in CTFd (tags table empty); it is encoded by point value,
# matching the kickoff deck's 4 difficulties.
def difficulty(value):
    if value < 300:
        return "Intro"
    if value < 500:
        return "Easy"
    if value < 1000:
        return "Medium"
    if value < 1500:
        return "Hard"
    return "Insane"

# Schools: no custom registration field and affiliation is ~always blank, so derive the
# school from the registered email domain (only the domain is ever printed).
SCHOOLS = {
    "wm.edu": "William & Mary",
    "vt.edu": "Virginia Tech",
    "cnu.edu": "Christopher Newport University",
    "vcu.edu": "Virginia Commonwealth University",
    "gmu.edu": "George Mason University",
    "virginia.edu": "University of Virginia",
    "odu.edu": "Old Dominion University",
    "nsu.edu": "Norfolk State University",
    "jmu.edu": "James Madison University",
    "radford.edu": "Radford University",
    "liberty.edu": "Liberty University",
    "richmond.edu": "University of Richmond",
    "vmi.edu": "Virginia Military Institute",
    "hamptonu.edu": "Hampton University",
    "umw.edu": "University of Mary Washington",
    "longwood.edu": "Longwood University",
    "wlu.edu": "Washington and Lee University",
    "vsu.edu": "Virginia State University",
    "marymount.edu": "Marymount University",
    "regent.edu": "Regent University",
    "vwu.edu": "Virginia Wesleyan University",
    "tcc.edu": "Tidewater Community College",
    "email.vccs.edu": "VCCS (community college)",
    "vccs.edu": "VCCS (community college)",
    "umd.edu": "University of Maryland",
    "terpmail.umd.edu": "University of Maryland",
}
AFFIL_ALIASES = {
    "w&m": "William & Mary", "wm": "William & Mary", "william and mary": "William & Mary",
    "william & mary": "William & Mary", "college of william and mary": "William & Mary",
    "vt": "Virginia Tech", "virginia tech": "Virginia Tech", "virginia polytechnic institute": "Virginia Tech",
    "cnu": "Christopher Newport University", "vcu": "Virginia Commonwealth University",
    "gmu": "George Mason University", "george mason": "George Mason University",
    "uva": "University of Virginia", "odu": "Old Dominion University", "nsu": "Norfolk State University",
    "jmu": "James Madison University",
}


def school_from_domain(domain):
    d = domain.lower().strip()
    parts = d.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in SCHOOLS:
            return cand, SCHOOLS[cand]
    base = ".".join(parts[-2:]) if len(parts) >= 2 else d
    if base.endswith(".edu"):
        return base, base  # unknown .edu: keep the registered domain as the school key
    return base, None


def latest_zip():
    pat = re.compile(r"(\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2})\.zip$")
    cands = []
    for p in ARCHIVE.glob("*.zip"):
        m = pat.search(p.name)
        if m:
            cands.append((m.group(1), p))
    if not cands:
        sys.exit(f"no CTFd export zips in {ARCHIVE}")
    return max(cands)[1]


def export_time(path):
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})_(\d{2})_(\d{2})\.zip$", path.name)
    if not m:
        return None
    return dt.datetime(*map(int, m.groups()), tzinfo=dt.timezone.utc)


def parse_date(s):
    if not s:
        return None
    s = s.replace("Z", "")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d.replace(tzinfo=dt.timezone.utc) if d.tzinfo is None else d  # CTFd stores UTC


def fmt(d):
    return d.astimezone(EDT).strftime("%a %b %d %I:%M %p EDT") if d else "n/a"


class Export:
    def __init__(self, path):
        self.z = zipfile.ZipFile(path)
        self.names = set(self.z.namelist())

    def table(self, name):
        n = f"db/{name}.json"
        if n not in self.names:
            return []
        raw = self.z.read(n)
        if not raw.strip():
            return []
        d = json.loads(raw)
        if isinstance(d, dict):
            return d.get("results", [])
        return d


def compute(path):
    ex = Export(path)
    cfg = {c["key"]: c["value"] for c in ex.table("config")}
    teams = {t["id"]: t for t in ex.table("teams")}
    users = {u["id"]: u for u in ex.table("users")}
    chals = {c["id"]: c for c in ex.table("challenges")}
    dyn = {d["id"]: d for d in ex.table("dynamic_challenge")}
    solves = ex.table("solves")
    awards = ex.table("awards")
    subs = ex.table("submissions")
    flags = ex.table("flags")
    fields = {f["id"]: f for f in ex.table("fields")}
    field_entries = ex.table("field_entries")
    sub_by_id = {s["id"]: s for s in subs}

    freeze = None
    if cfg.get("freeze"):
        try:
            freeze = dt.datetime.fromtimestamp(int(cfg["freeze"]), dt.timezone.utc)
        except (TypeError, ValueError):
            freeze = None

    def chal_value(cid):
        c = chals.get(cid)
        if not c:
            return 0
        # CTFd keeps the current (decayed) value in challenges.value for dynamic challenges too.
        return c.get("value") or 0

    def team_ok(tid):
        t = teams.get(tid)
        return t is not None and not t.get("hidden") and not t.get("banned")

    def user_ok(u):
        return u and u.get("type") != "admin" and not u.get("hidden") and not u.get("banned")

    # ---- score events (CTFd get_standings semantics) ----
    events = defaultdict(list)  # team_id -> [(date, order_id, points, kind, cid)]
    solve_rows = []
    for s in solves:
        tid = s.get("team_id")
        if not team_ok(tid):
            continue
        sub = sub_by_id.get(s["id"], {})
        d = parse_date(s.get("date") or sub.get("date"))
        if freeze and d and d >= freeze:
            continue
        v = chal_value(s["challenge_id"])
        solve_rows.append((d, s["id"], tid, s.get("user_id"), s["challenge_id"]))
        if v != 0:
            events[tid].append((d, s["id"], v, "solve", s["challenge_id"]))
    for a in awards:
        tid = a.get("team_id")
        if tid is None and a.get("user_id") in users:
            tid = users[a["user_id"]].get("team_id")
        if not team_ok(tid):
            continue
        d = parse_date(a.get("date"))
        if freeze and d and d >= freeze:
            continue
        if a.get("value"):
            events[tid].append((d, 10**9 + a["id"], a["value"], "award", None))

    members = defaultdict(list)
    for u in sorted(users.values(), key=lambda u: u["id"]):
        if user_ok(u) and u.get("team_id") in teams:
            members[u["team_id"]].append(u["name"])

    board = []
    for tid, evs in events.items():
        score = sum(e[2] for e in evs)
        if score == 0:
            continue
        last = max(evs, key=lambda e: (e[0] or dt.datetime.min.replace(tzinfo=dt.timezone.utc), e[1]))
        board.append({"team_id": tid, "team": teams[tid]["name"].strip(), "score": score,
                      "last": last[0], "last_id": last[1], "members": members.get(tid, []),
                      "solves": sum(1 for e in evs if e[3] == "solve")})
    # Tie-break: whoever reached the score first (earliest last scoring event).
    far = dt.datetime.max.replace(tzinfo=dt.timezone.utc)
    board.sort(key=lambda r: (-r["score"], r["last"] or far, r["last_id"]))
    for i, r in enumerate(board, 1):
        r["rank"] = i
        r["eligible"] = r["score"] >= ELIGIBLE_MIN

    # ---- counts ----
    vis_teams = [t for t in teams.values() if team_ok(t["id"])]
    teams_with_members = [t for t in vis_teams if members.get(t["id"])]
    teams_with_solve = {r[2] for r in solve_rows}
    students = [u for u in users.values() if user_ok(u)]
    students_with_solve = {r[3] for r in solve_rows if user_ok(users.get(r[3]))}
    students_on_team = [u for u in students if u.get("team_id") in teams and team_ok(u.get("team_id"))]

    # ---- schools ----
    school_raw = Counter()  # raw domain/affiliation -> count
    school_map = {}
    user_school = {}
    # custom registration fields mentioning school/university, if any exist
    school_field_ids = {fid for fid, f in fields.items()
                        if re.search(r"school|univ|college|institution", (f.get("name") or ""), re.I)}
    field_school = {}
    for fe in field_entries:
        if fe.get("field_id") in school_field_ids and fe.get("user_id"):
            v = str(fe.get("value") or "").strip()
            if v:
                field_school[fe["user_id"]] = v
    for u in students_on_team:
        raw = None
        name = None
        if u["id"] in field_school:
            raw = "field:" + field_school[u["id"]]
            key = re.sub(r"\s+", " ", field_school[u["id"]]).strip().lower()
            name = AFFIL_ALIASES.get(key, field_school[u["id"]].strip())
        elif u.get("email") and "@" in u["email"]:
            key, name = school_from_domain(u["email"].rsplit("@", 1)[1])
            raw = "@" + u["email"].rsplit("@", 1)[1].lower()
        if not name and u.get("affiliation"):
            key = re.sub(r"\s+", " ", u["affiliation"]).strip().lower()
            raw = "affiliation:" + u["affiliation"].strip()
            name = AFFIL_ALIASES.get(key, u["affiliation"].strip())
        raw = raw or "(none)"
        school_raw[raw] += 1
        school_map[raw] = name or "(unknown)"
        if name:
            user_school[u["id"]] = name
    schools = Counter(user_school.values())

    # ---- challenges ----
    solve_count = Counter()
    first_blood = {}
    for d, sid, tid, uid, cid in sorted(solve_rows, key=lambda r: (r[0] or far, r[1])):
        solve_count[cid] += 1
        if cid not in first_blood:
            first_blood[cid] = (teams[tid]["name"].strip(), d)
    chal_list = []
    for c in sorted(chals.values(), key=lambda c: (c["value"], c["category"].lower(), c["name"].lower())):
        if c.get("state") == "hidden" and not solve_count[c["id"]]:
            continue
        chal_list.append({"id": c["id"], "name": c["name"].strip(), "category": c["category"].strip(),
                          "value": chal_value(c["id"]), "difficulty": difficulty(chal_value(c["id"])),
                          "solves": solve_count[c["id"]], "hidden": c.get("state") == "hidden",
                          "first_blood": first_blood.get(c["id"], (None, None))[0],
                          "first_blood_at": fmt(first_blood.get(c["id"], (None, None))[1]) if c["id"] in first_blood else None})
    visible = [c for c in chal_list if not c["hidden"]]
    by_diff = {}
    for c in visible:
        b = by_diff.setdefault(c["difficulty"], {"challenges": 0, "solves": 0})
        b["challenges"] += 1
        b["solves"] += c["solves"]

    sub_types = Counter(s.get("type") for s in subs)
    team_subs = [s for s in subs if team_ok(s.get("team_id"))]
    last_solve = max((r[0] for r in solve_rows if r[0]), default=None)
    first_solve = min((r[0] for r in solve_rows if r[0]), default=None)

    eligible = [r for r in board if r["eligible"]]
    winners = eligible[:3]
    honorable = eligible[3:8]

    def pub(r):
        return {"rank": r["rank"], "team": r["team"], "score": r["score"],
                "members": r["members"], "eligible": r["eligible"], "solves": r["solves"]}

    funny = []
    if FUNNY.exists():
        for line in FUNNY.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                funny.append(line.strip())

    exp_t = export_time(path)
    stats = {
        "generated_at": dt.datetime.now(dt.timezone.utc).astimezone(EDT).strftime("%Y-%m-%d %H:%M EDT"),
        "export_file": path.name,
        "export_time": fmt(exp_t),
        "data_as_of": fmt(last_solve),
        "ctf_name": cfg.get("ctf_name"),
        "freeze": fmt(freeze) if freeze else None,
        "counts": {
            "teams": len(teams_with_members),
            "teams_with_solve": len(teams_with_solve),
            "students": len(students_on_team),
            "students_with_solve": len(students_with_solve),
            "schools": len(schools),
            "challenges": len(visible),
            "solves": len(solve_rows),
            "submissions": len(team_subs),
            "correct_submissions": sum(1 for s in team_subs if s.get("type") == "correct"),
            "incorrect_submissions": sum(1 for s in team_subs if s.get("type") == "incorrect"),
        },
        "schools": [{"name": n, "students": c} for n, c in schools.most_common()],
        "difficulty": by_diff,
        "challenges": [{k: c[k] for k in ("name", "category", "value", "difficulty", "solves", "first_blood")}
                       for c in visible],
        "top10": [pub(r) for r in board[:10]],
        "winners": [dict(pub(r), place=i + 1, prize=PRIZES[i]) for i, r in enumerate(winners)],
        "honorable": [dict(pub(r), place=i + 4) for i, r in enumerate(honorable)],
        "eligible_min": ELIGIBLE_MIN,
        "funny_flags": funny,
    }
    extra = {"board": board, "school_raw": school_raw, "school_map": school_map, "chal_list": chal_list,
             "flags": flags, "chals": chals, "sub_types": sub_types, "first_solve": first_solve,
             "vis_teams": vis_teams, "students": students, "exp_t": exp_t, "cfg": cfg}
    return stats, extra


def report(path, stats, x):
    c = stats["counts"]
    p = print
    p(f"== {stats['ctf_name']} closing stats ==")
    p(f"export file : {path.name}")
    p(f"export time : {stats['export_time']}   (filename timestamp, UTC->EDT)")
    p(f"data as of  : last counted solve {stats['data_as_of']}; first {fmt(x['first_solve'])}")
    p(f"CTF window  : {fmt(dt.datetime.fromtimestamp(int(x['cfg']['start']), dt.timezone.utc)) if x['cfg'].get('start') else 'n/a'}"
      f" -> {fmt(dt.datetime.fromtimestamp(int(x['cfg']['end']), dt.timezone.utc)) if x['cfg'].get('end') else 'n/a'}"
      f"   freeze: {stats['freeze'] or 'not set'}")
    p()
    p(f"Teams       : {c['teams']} non-hidden teams with >=1 member  ({c['teams_with_solve']} with >=1 solve;"
      f" {len(x['vis_teams'])} non-hidden team rows total)")
    p(f"Students    : {c['students']} non-hidden non-admin users on a non-hidden team  ({c['students_with_solve']} with >=1 solve;"
      f" {len(x['students'])} non-hidden non-admin users total)")
    p(f"Schools     : {c['schools']}")
    for s in stats["schools"]:
        p(f"    {s['students']:>3}  {s['name']}")
    p("  raw -> normalized (students):")
    for raw, n in x["school_raw"].most_common():
        p(f"    {n:>3}  {raw:<28} -> {x['school_map'][raw]}")
    p()
    p(f"Challenges  : {c['challenges']} visible; {c['solves']} solves; submissions {c['submissions']}"
      f" ({c['correct_submissions']} correct, {c['incorrect_submissions']} incorrect)")
    order = ["Intro", "Easy", "Medium", "Hard", "Insane"]
    for d in order:
        if d in stats["difficulty"]:
            b = stats["difficulty"][d]
            p(f"    {d:<7} {b['challenges']:>2} challenges, {b['solves']:>3} solves")
    p("  difficulty by points: <300 Intro, 300 Easy, 500 Medium, 1000 Hard, >=1500 Insane")
    p(f"  {'pts':>5} {'diff':<7} {'solves':>6}  {'challenge':<34} {'category':<15} first blood")
    for ch in x["chal_list"]:
        hid = " [HIDDEN]" if ch["hidden"] else ""
        fb = f"{ch['first_blood']} @ {ch['first_blood_at']}" if ch["first_blood"] else "-"
        p(f"  {ch['value']:>5} {ch['difficulty']:<7} {ch['solves']:>6}  {(ch['name'] + hid)[:34]:<34} {ch['category'][:15]:<15} {fb}")
    p()
    p(f"Scoreboard top 10 (eligible = score >= {ELIGIBLE_MIN}; ties -> earliest last score):")
    for r in x["board"][:10]:
        p(f"  {r['rank']:>2}. {r['team']:<28} {r['score']:>6}  {'ELIGIBLE' if r['eligible'] else 'not eligible':<12}"
          f" last={fmt(r['last'])}  [{', '.join(r['members'])}]")
    ties = Counter(r["score"] for r in x["board"][:12])
    tied = [s for s, n in ties.items() if n > 1]
    if tied:
        p(f"  NOTE: tied scores in top 12: {tied} (broken by earliest last scoring solve)")
    p(f"  eligible teams total: {sum(1 for r in x['board'] if r['eligible'])}")
    p()
    p("PRIZES (top 3 eligible):")
    for w in stats["winners"]:
        p(f"  {w['place']}. {w['team']} ({w['score']} pts, board rank {w['rank']}) {w['prize']}  [{', '.join(w['members'])}]")
    p("Honorable mentions (eligible places 4-8):")
    for h in stats["honorable"]:
        p(f"  {h['place']}. {h['team']} ({h['score']} pts, board rank {h['rank']})  [{', '.join(h['members'])}]")
    p()
    p("Funny-flag candidates (static flags; pick some into closing-2026-slides/funny_flags.txt):")
    for f in sorted(x["flags"], key=lambda f: f["challenge_id"]):
        ch = x["chals"].get(f["challenge_id"], {})
        p(f"  [{ch.get('name', '?').strip()[:28]}] ({f.get('type')}) {f.get('content')}")
    p(f"Funny flags currently on deck: {len(stats['funny_flags'])}")


def inject(stats):
    html = DECK.read_text(encoding="utf-8")
    blob = json.dumps(stats, ensure_ascii=False, indent=1).replace("</", "<\\/")
    pat = re.compile(r'(<script id="stats" type="application/json">)(.*?)(</script>)', re.S)
    if not pat.search(html):
        print("WARN: no <script id=\"stats\"> block in deck; deck not updated")
        return
    html = pat.sub(lambda m: m.group(1) + "\n" + blob + "\n    " + m.group(3), html, count=1)
    DECK.write_text(html, encoding="utf-8")
    print(f"deck updated: {DECK.relative_to(REPO)}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = Path(args[0]).expanduser().resolve() if args else latest_zip()
    stats, extra = compute(path)
    report(path, stats, extra)
    print()
    STATS_JSON.write_text(json.dumps(stats, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {STATS_JSON.relative_to(REPO)}")
    if "--no-deck" not in sys.argv:
        inject(stats)


if __name__ == "__main__":
    main()

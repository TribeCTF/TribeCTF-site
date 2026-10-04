#!/usr/bin/env python3
"""CAGE stats for the closing deck.

Two parts:
  * ctfd_cage(...)  -- recomputed from the CTFd export on every closing_stats.py run
                       (cage-only challenges = CTFd category "Cage").
  * queue_stats(db) -- aggregates from a COPY of the CAGE queue SQLite DB. Run once:
                         python3 scripts/cage_stats.py /path/to/cage-copy.db
                       It stores a snapshot under stats["cage"]["queue"] in
                       closing-2026-slides/stats.json; closing_stats.py carries it forward.
Only aggregates and team names leave this module (no emails, no per-person data).
"""
import datetime as dt
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

CAGE_CATEGORY = "cage"
EDT = dt.timezone(dt.timedelta(hours=-4), "EDT")
OVERNIGHT = (0, 6)  # session start hour range in EDT [0, 6)


def _ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _fmt(d):
    return d.astimezone(EDT).strftime("%a %-I:%M %p") if d else None


def ctfd_cage(chal_list, solve_rows, teams):
    """chal_list: closing_stats chal_list; solve_rows: (date, id, team_id, user_id, chal_id)."""
    cage = {c["id"]: c for c in chal_list if c["category"].strip().lower() == CAGE_CATEGORY and not c["hidden"]}
    rows = sorted((r for r in solve_rows if r[4] in cage), key=lambda r: (r[0] or dt.datetime.max.replace(tzinfo=dt.timezone.utc), r[1]))
    per_team = Counter(r[2] for r in rows)
    first = rows[0] if rows else None
    unsolved = [c["name"] for c in cage.values() if not c["solves"]]
    top = per_team.most_common()
    best = [teams[t]["name"].strip() for t, n in top if n == top[0][1]] if top else []
    return {
        "challenges": len(cage),
        "points": sum(c["value"] for c in cage.values()),
        "solves": len(rows),
        "teams_solved": len(per_team),
        "first_solve_team": teams[first[2]]["name"].strip() if first else None,
        "first_solve_at": _fmt(first[0]) if first else None,
        "most_solves": top[0][1] if top else 0,
        "most_solves_teams": best,
        "all_solved_teams": [teams[t]["name"].strip() for t, n in top if n == len(cage)],
        "unsolved": unsolved,
        "list": [{"name": c["name"], "value": c["value"], "solves": c["solves"],
                  "first_blood": c["first_blood"]} for c in sorted(cage.values(), key=lambda c: c["value"])],
    }


def queue_stats(db_path):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    q = lambda sql: con.execute(sql).fetchall()
    ev = q("select ts, kind, station_id, team_id, detail from events order by id")

    # Sessions: pair start -> end per station (overdue/end close it).
    open_s, sessions = {}, []
    for ts, kind, st, team, _ in ev:
        if kind == "start":
            open_s[st] = (_ts(ts), team)
        elif kind == "end" and st in open_s:
            s, team0 = open_s.pop(st)
            sessions.append((s, _ts(ts), team0))
    last_ts = _ts(ev[-1][0])
    for st, (s, team0) in open_s.items():  # still running at snapshot time
        sessions.append((s, last_ts, team0))
    minutes = sum((e - s).total_seconds() for s, e, _ in sessions) / 60

    # Max concurrent stations in use, and minutes with every station occupied.
    pts = sorted([(s, 1) for s, _, _ in sessions] + [(e, -1) for _, e, _ in sessions], key=lambda p: (p[0], p[1]))
    cur = peak = 0
    full_min, full_since = 0.0, None
    nstations = q("select count(*) from stations")[0][0]
    for t, d in pts:
        cur += d
        peak = max(peak, cur)
        if cur == nstations and full_since is None:
            full_since = t
        elif cur < nstations and full_since is not None:
            full_min += (t - full_since).total_seconds() / 60
            full_since = None

    # Queue length replay: request created -> invited (or cancelled).
    cancel_at = {}
    for ts, kind, _, _, detail in ev:
        if kind == "cancel" and detail and detail.startswith("request "):
            cancel_at[int(detail.split()[1])] = _ts(ts)
    qpts = []
    for rid, created, invited in q("select id, created_at, invited_at from requests"):
        c = _ts(created)
        leave = _ts(invited) or cancel_at.get(rid)
        qpts.append((c, 1))
        if leave:
            qpts.append((leave, -1))
    qpts.sort(key=lambda p: (p[0], p[1]))
    cur = qpeak = 0
    qpeak_at = None
    for t, d in qpts:
        cur += d
        if cur > qpeak:
            qpeak, qpeak_at = cur, t

    by_hour = Counter(s.astimezone(EDT).strftime("%a %-I %p") for s, _, _ in sessions)
    busiest_hour, busiest_n = by_hour.most_common(1)[0] if by_hour else (None, 0)
    overnight = [s for s, _, _ in sessions if OVERNIGHT[0] <= s.astimezone(EDT).hour < OVERNIGHT[1]]
    team_min = defaultdict(float)
    for s, e, team in sessions:
        team_min[team] += (e - s).total_seconds() / 60
    names = dict(q("select team_id, name from teams"))
    first_s = min(s for s, _, _ in sessions)
    last_e = max(e for _, e, _ in sessions)
    return {
        "snapshot_at": _fmt(last_ts),
        "stations": nstations,
        "teams": len({t for _, _, t in sessions}),
        "sessions": len(sessions),
        "requests": len(q("select id from requests")),
        "hours": round(minutes / 60, 1),
        "hours_whole": round(minutes / 60),
        "avg_session_min": round(minutes / len(sessions)) if sessions else 0,
        "teams_full_budget": q("select count(*) from teams where used_min >= 120")[0][0],
        "peak_stations": peak,
        "all_stations_full_hours": round(full_min / 60, 1),
        "peak_queue": qpeak,
        "peak_queue_at": _fmt(qpeak_at),
        "busiest_hour": busiest_hour,
        "busiest_hour_sessions": busiest_n,
        "overnight_sessions": len(overnight),
        "overnight_window": "12-6 AM",
        "first_session": _fmt(first_s),
        "last_session_end": _fmt(last_e),
        "most_time_team": names.get(max(team_min, key=team_min.get)) if team_min else None,
        "most_time_hours": round(max(team_min.values()) / 60, 1) if team_min else 0,
    }


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: cage_stats.py /path/to/COPY-of-cage.db")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import closing_stats as cs
    snap = queue_stats(Path(sys.argv[1]).expanduser().resolve())
    stats = json.loads(cs.STATS_JSON.read_text(encoding="utf-8")) if cs.STATS_JSON.exists() else {}
    stats.setdefault("cage", {})["queue"] = snap
    cs.STATS_JSON.write_text(json.dumps(stats, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(snap, indent=1))
    print("queue snapshot saved; now run: python3 scripts/closing_stats.py")


if __name__ == "__main__":
    main()

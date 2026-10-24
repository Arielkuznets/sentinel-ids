# Contributing to SENTINEL IDS

## Set up

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest                    # must be green before and after every change
python scripts/make_samples.py      # reference captures, for --replay
```

Live capture needs [Npcap](https://npcap.com); nothing else does – replay, the
demos and the whole test suite run without it.

## Rules the codebase keeps

- **No numbers in code.** Every threshold, window, timeout and limit lives in
  `config/config.yaml` and reaches its class as a constructor argument from
  `main.py`. A display-only constant (how many rows the dashboard keeps) may live
  next to the code that draws it.
- **Packet time, never the wall clock**, for anything that measures a window –
  detectors, deduplication, the baseline, retention. See
  [ADR 0003](docs/adr/0003-packet-time.md).
- **Every packet field can be `None`.** ARP has no ports; IPv6 with extension
  headers reads as protocol `OTHER`. A detector checks before it uses a field.
- **Every per-source structure is bounded.** Sources are spoofable; anything keyed
  on one needs a sweep, a cap or an expiry.
- **Comments explain why, once.** The code says what; a comment earns its place by
  saying what the code cannot – and a shared reason is written in one place, not
  at every call site.

## Tests

- Drive a detector through `_process(packet)` with injected timestamps – no
  threads, no `sleep`. The time-dependent queries take `now`.
- Each test gets its own SQLite file from the `session_factory` fixture.
- Build what is under test from the real `config.yaml` (see the `scorer` fixture
  and `tests/test_samples.py`), so a renamed key or a moved threshold fails a test
  instead of a demo.
- A docstring or comment in a test states the behaviour it pins down – never which
  module happens to call the code.

## Adding a detector

1. A class in `core/detectors/` with the same shape as the others: it takes its
   own packet queue and the shared alert queue, runs `_process` on its own thread,
   and emits `Alert(type, severity, src_ip, timestamp, details)`.
2. Its thresholds in `config.yaml`, wired in `main.py` with
   `pkt_queue.subscribe()`, and added to the `pipeline` list so it starts and
   stops with everything else.
3. A type weight under `alerts.scoring.type_weights`.
4. Unit tests driving `_process`, a scenario in `scripts/make_samples.py`, and its
   expected alerts in `tests/test_samples.py` and `DEMO.md`.

## Git

- Branch from `dev`: `feature/<name>`, `fix/<name>` or `docs/<name>`.
- Merge back with `git merge --no-ff`, so every branch stays a visible block in
  the history; `dev` reaches `main` the same way at the end of a phase, with an
  annotated tag `vX.Y.0`.
- Commit subjects are imperative, prefixed (`feat:`, `fix:`, `refactor:`, `test:`,
  `docs:`) and under 60 characters. The body says why.
- Never commit captured traffic (`captures/`), a database, the GeoLite2 file, or
  local session files – `.gitignore` covers each of them.

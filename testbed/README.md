# Testbed measurements (RQ1, RQ2 n-sweep, RQ4)

These experiments need the physical/emulated testbed of Section VII
(Raspberry Pi 4B gateway, Xeon server with Mininet/Ryu/OVS/ZFLOW, Open5GS with
BMv2). They cannot be run from the reference implementation alone.

## 1. Log format

Each controller adapter and the UPT appends one JSON object per event to a
JSON-lines file. Clocks must be synchronised (PTP preferred, NTP otherwise);
record the measured offset.

```json
{"run": 17, "exp": "rq1", "stage": "spa_mtd_start", "t": 1732171234.123456, "host": "open5gs"}
```

Required `stage` names (start/end pairs, `t` in seconds):

| Experiment | stages |
|---|---|
| RQ1 | `spa_mtd_start`, `spa_mtd_end`, `parse_start`, `parse_end`, `compose_start`, `compose_end`, `verify_start`, `verify_end`, `dnos_start`, `dnos_end`, `of_ebpf_start`, `of_ebpf_end`, `wg_start`, `wg_end` |
| RQ2 (n-sweep) | same as RQ1, plus a field `"n": <enterprise resources>` and `"m": <DNOS subsets>` on every line |
| RQ4 | `detect` (anomaly observed by source controller), `publish` (trust event sent), `eval_end` (UPT finished re-evaluation), `target_install_end` (target rules deleted), plus `{"stage": "malicious_flow", "reached_target": true/false}` per attack flow |

`T_converge` = `wg_end` (or the last `*_end`) minus `spa_mtd_start`.
`T_rev` = `target_install_end` minus `detect`.

## 2. Protocol

* RQ1: 30 or more runs of the paramedic workflow (Section VIII-B). Restart
  the flow between runs; do not reuse grants.
* RQ2 n-sweep: n in {50, 100, 250, 500, 1000, 2000} enterprise resources,
  30 runs each. If Mininet cannot host 2000 hosts, use fewer hosts per switch
  with additional virtual IPs per host and state this in the paper.
* RQ4: scenarios S1-S3 (Section VIII-E), 30 runs each, siloed
  (UPT trust events disabled) and UPT-coordinated. Also sweep
  theta in {0.7, 0.8, 0.9} and the decay rates mu_a x {0.5, 1, 2}.
* Measure c_r on the mobile testbed: time from a shuffle to the first packet
  on the new address of an existing ES-SPA session.

## 3. Analysis

```
python testbed/analyze.py logs/*.jsonl > results/testbed_summary.json
```

prints mean, median, p95 and a 95% bootstrap confidence interval per stage and
experiment, and emits the LaTeX rows for Tables IV and V of the paper.

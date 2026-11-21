# IILS / UPT reference implementation and evaluation artifact

Companion artifact for *Semantics-Preserving Intent Translation for
Cross-Domain Zero Trust Enforcement across IoT, Enterprise, and 5G/6G Networks*.

| Path | What it is | Paper section |
|---|---|---|
| `upt/iils.py` | IILS data model: prefixes, boundary atoms, policies, trust context | IV-A, IV-E |
| `upt/core.py` | Lattice meet (Lemma 1), admission and leases, QoS negotiation, placement, local veto | IV-C, V-C to V-F |
| `upt/translate.py` | Translators to iptables, OpenFlow (value/mask ports) and P4 (IPv6, NAT64), with native renderers | V-B, Table III |
| `upt/verify.py` | Z3 encoding, two-query soundness check, completeness, obligation checks, concrete interpreter | VI |
| `upt/grant.py` | Algorithm 1, capability profiles, grant store with target-first revocation | V-C, V-E |
| `yang/iils@2026-11-21.yang` | YANG 1.1 module (validates with `pyang --strict`) | IV-F |
| `tests/test_upt.py` | Property tests: Lemma 1, Theorem 2, Propositions 1-2, revocation order, shadowing, wildcard subject | VII |
| `experiments/` | Corpus generator, RQ2/RQ3/RQ5 scripts, Figure 3 | VIII |
| `testbed/` | Log format, protocol and analysis script for RQ1, the DNOS sweep and RQ4 | VIII |
| `results/` | Outputs of the software experiments reported in the paper | VIII |

## Reproduce the software results

```
pip install -r requirements.txt
python -m pytest -q tests
python experiments/rq3_mutation.py 400 21      # Table V, T_ver on the corpus   (~2 min)
python experiments/rq2_cost.py                 # Figure 3                        (~10 min)
python experiments/rq5_baselines.py 1000 0.5 31  # Table VII                     (~30 s)
python experiments/make_figs.py
```

Results in `results/` were produced on a 2-vCPU Intel Xeon (2.1 GHz) VM with
7 GB RAM, Python 3.13 and z3-solver 5.4.1 (the paper reports this machine).

## What is *not* reproduced here

RQ1 (convergence), the enterprise DNOS sweep of RQ2, and RQ4 (containment)
need the physical/emulated testbed. See `testbed/README.md`.

## Modelling notes

* Baselines B1 and B2 in `rq5_baselines.py` re-implement the *composition
  semantics* of an I2NSF-style pipeline and of OPA at every enforcement point;
  they are not full deployments of those systems.
* Capability profiles for the enterprise and mobile cipher suites are
  assumptions (marked in Table III of the paper) until confirmed against the
  implementations.
* `c_r = 0.24 s` is derived from the measured 99.92% session stability at a
  300 s shuffle interval with a 2 s rule overlap (Phase III paper).

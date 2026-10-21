# Formula and experiment design

The implementation instantiates the proposal's five-variable idea with a small,
explicit formula. These numerical choices are provisional, not a formula supplied
or validated by the proposal.

## Score direction

`BehaviorRisk` is in `[0, 1]`, where larger means more risky. Trust is
`T = 1 - BehaviorRisk`. The threshold is the **minimum acceptable trust**.
An increase in the threshold tightens access. Quarantine occurs when `T < threshold`;
equality is allowed and counts as a near-boundary observation.

## Inputs

| Symbol | Code name | Definition before the current decision |
| --- | --- | --- |
| C | `criticality` | Device importance assigned at registration, from 0 to 1 |
| H | `violation_history` | Decaying pressure from earlier near-boundary or quarantined observations |
| V | `score_velocity` | Positive fall in trust since the preceding observation, divided by 0.15 and clipped |
| B | `personal_baseline` | Positive excess risk above the device baseline, divided by 0.40 and clipped |
| N | `network_context` | Supplied network risk context, from 0 to 1 |

Here velocity is change **per observation**, not change per second. Observation
frequency must be controlled during experiments or this definition must be replaced.

The static threshold is fixed at onboarding:

```text
static = clip(0.50 + 0.08*C, 0.10, 0.95)
```

The adaptive candidate is:

```text
candidate = 0.50 + 0.08*C + 0.22*H + 0.10*V + 0.08*B + 0.06*N
```

If the previous observation was near the boundary, the candidate is floored at
the previous threshold. The final value is clipped to `[0.10, 0.95]`. This prevents
relaxation during consecutive probes; it is not a proof of globally monotone trust
decisions or universal evasion resistance.

After a decision, a non-quarantined device is near the boundary when
`0 <= T - threshold <= 0.08`. History pressure becomes:

```text
H_next = clip(0.90*H + 0.35*suspicious, 0, 1)
```

`suspicious` is 1 for a near-boundary or quarantine decision, otherwise 0.
Counting near-boundary events in H is an explicit design extension of literal
threshold violations. Keep this choice visible in the methodology and ablate it.

The personal risk baseline initially equals 0.15. Once five eligible observations
exist, it becomes the mean of the most recent five. Only allowed, non-probing
observations with risk at most 0.25 update it. This gate limits contamination but
does not solve baseline poisoning or genuine benign concept drift.

## State and audit choices (updated in v0.3)

- The scoring engine still keeps bounded, independent device state in memory.
- The API now persists registration seeds, accepted observations, complete decisions,
  event IDs and rejected-event audit records in SQLite. On restart it replays the
  saved observations through the unchanged algorithm, restoring baseline buffers,
  history pressure, probe streaks, previous trust, ordering and quarantine latches.
- Event acceptance, its decision and its blockchain outbox entry commit in one
  transaction before the scoring engine advances memory. A failed write leaves
  the event unapplied; an accepted event is recognized on retry after restart.
- The offline simulation still writes CSV with the original DecisionLogger.
- One API process owns each database. An OS file lock rejects another writer.
- Quarantine remains latched; a controlled release design is future work.
- Legacy explicit null risk retains its original quarantine behavior. The Member 2
  event route rejects invalid-quality evidence and requires risk for valid/partial
  evidence; missing AI traffic never becomes a fabricated risk of zero.
- Authentication, persistent identity, 15-second freshness and 2-second future-skew
  defaults are implemented at the API boundary, independently of the algorithm.

In blockchain mode, ledger criticality is still `(level - 1) / 4`. The pre-existing
adapter exports a 0-100 effective trust value with a bounded policy adjustment
where necessary to preserve quarantine after rounding. The unadjusted score is
retained in the audit/evidence and is what offline metrics use. See
[BLOCKCHAIN_INTEGRATION.md](BLOCKCHAIN_INTEGRATION.md) and
[MEMBER2_CONTRACT.md](MEMBER2_CONTRACT.md) for the current integration semantics.

## Comparison protocol

Each synthetic device is registered in both engines with the same criticality.
The runner creates one observation and sends it unchanged to both engines. Each
engine has independent state. Ground-truth labels never enter the scoring API or
core; `simulation.py` attaches them to the completed decisions.

The three probe generators use a reference threshold and a margin of 0.025:

- Fixed margin: choose risk so trust is just above the reference threshold.
- Slow drift: increase risk by 0.025 per attack round, limited by that margin.
- Randomised: sample below the same risk ceiling within a band of width 0.12.

With `--feedback static`, the reference is the static threshold. This deliberately
makes the static baseline evadeable for these generated cases. With
`--feedback adaptive`, both engines receive a trace responding to the previous
adaptive threshold. That reference is stale by one round; it does not model an
omniscient attacker solving the next formula exactly. Post-quarantine rows are
virtual observations used to finish the paired trace, not accepted network traffic.

The benign risk signal varies over time, and one in five benign profiles includes
occasional larger bursts. Neither those profile frequencies nor the generated risk
distribution are estimates of real IoT traffic.

## Metrics

- Catch rate: attack devices first quarantined during attack rounds, divided by
  eligible attack devices. Devices caught during warm-up are reported separately
  as `preAttackQuarantines` and excluded from this denominator.
- Catch within 10 rounds: the same denominator, with first quarantine in attack
  rounds 1-10. If a run has fewer than 10 rounds this is only the observed shorter horizon.
- False-positive rate: wholly benign devices quarantined at any point, divided
  by wholly benign devices.
- Median time to quarantine is calculated **only among caught devices**. Uncaught
  device counts remain explicit; the median is not an overall survival estimate.
- Indicator-to-quarantine rounds count from the first near-boundary or quarantine
  indicator in the attack phase. Immediate quarantine has delay zero.
- Compute latency covers feature calculation, threshold computation, and candidate
  state updates. It excludes state copying, locking, logs, HTTP, and enforcement.
  It cannot be presented as end-to-end edge latency.

Empty denominators and absent caught cases produce JSON `null`, not artificial zeros.
Use multiple seeds and confidence intervals for research evaluation. The runner
supports one-feature weight ablations; this first version does not automate a
full multi-seed study, fitting, plots, or cross-dataset evaluation.


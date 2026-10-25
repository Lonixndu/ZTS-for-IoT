# Continue the research from this starter

1. Review the score direction, history pressure rule, baseline update policy,
   and provisional weights with the supervisor. Record the chosen formula and
   alternatives in the research decision log.
2. Agree on the real `BehaviorRisk` contract with the AI-component owner. Define
   whether it is calibrated, how missing or delayed input is signalled, and how
   each observation maps to a persistent device and time window.
3. Build the real-data adapter. CICIoT2023, Bot-IoT, TON_IoT, and UNSW-NB15 are
   named in the proposal, but no dataset adapter or dataset is included here.
   Preserve device and temporal context when constructing sequences. Do not
   simply treat arbitrary shuffled CSV rows as device histories.
4. Split data before tuning; keep test devices or time periods separate as the
   chosen protocol requires. Tune on training/validation partitions and freeze
   the parameters before the held-out and cross-dataset tests.
5. Extend the attack model to agents that understand the formula and forecast
   its updates, including cold-start and baseline-poisoning attempts. The current
   three generators are controlled risk sequences, not a full informed-adversary
   search or a Scapy/MQTT traffic testbed.
6. Run the static comparison and all five ablations over several seeds. Record
   false alarms, uncaught episodes, and uncertainty as well as successful catches.
   Evaluate additional fair baselines, including a tuned higher static threshold.
7. Run the new bridge adapter against the teammate's real Fabric network. Agree
   the effective-trust and reason-code conventions in `BLOCKCHAIN_INTEGRATION.md`,
   connect the history feed to the federated learning component, and implement
   actual network enforcement. Baseline/pressure persistence is implemented in v0.3.
8. Authentication and stale-feed reporting are implemented in v0.3. Agree and test
   downstream hold enforcement, a recovery policy and controlled quarantine release.
9. Measure end-to-end latency and 200-device operation on the actual Linux VM or
   Raspberry Pi target. The provided test timings are not edge-device benchmarks.
10. Record the dates of work actually performed and keep the corresponding code,
    tests, parameter snapshots, and experiment outputs as evidence.


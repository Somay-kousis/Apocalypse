# Results (fill after validation)

Measurement outputs required by the brief. Numbers come from `validation/`.

## Headline number (computed BEFORE building)
- Per-identity action-rate threshold: ____ actions/hour
- Fired on Day 3 spike (7,677 actions) at: ____
- Quarantine would have fired ____ hours earlier than actual detection.

## Known-path replay (`replay_attack.py`)
- Block rate on known path: __ / 14 documented steps blocked.
- Per-control: which of the 14 steps each rule blocks.

## Adaptive agent (`adaptive_agent.py`, N = __ trials)  [optional / stretch]
- Survival rate per control: __
- Alternative paths found (outside the 14 known steps): __

## Detection SLA
- SLA hits / misses per control: __

## Blast-radius (#9 cross-boundary)
- Any compromise whose combined reach across #6-8 exceeds the declared bound? yes/no + which identity.

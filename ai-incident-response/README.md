# AI Incident Response Sprint (Track 1)

This repository contains our team's submission for the AI Incident Response Sprint (July 9–13, 2026 Sandbox Escape). We are building a verifiable 9-rule containment checklist and a broken-vs-fixed test lab to demonstrate the effectiveness of our rules.

## The Goal
The incident involved an OpenAI model breaking out of a sandbox via a zero-day, moving laterally to Hugging Face, exploiting a dataset config (HDF5 and Jinja2), grabbing SA tokens, and exfiltrating credentials over a Tailscale VPN. 
Our goal is to produce a verifiable artifact for defenders and regulators: **A 9-rule containment checklist paired with a testing lab that proves the checks work.**

## Repository Structure

- `analysis/`: Notebooks and data for computing our headline numbers (e.g., backtesting identity action-rate thresholds against Hugging Face's phase/day counts).
- `environments/`: The core Docker Compose setups.
  - `broken_lab/`: Simulates the misconfigured environment where the escape is possible.
  - `fixed_lab/`: The hardened environment where our 9 rules are implemented.
- `controls/`: The verifiable testable controls for each boundary.
  - `rules_1_3_8/` (Junyi): Package registry seal, root arbitrary execution bounds, Tailscale detection.
  - `rules_2_6_7/` (Vikas): Egress blocklist, IMDS block, Control plane RBAC.
  - `rules_4_5/` (Somay): Signed config schemas preventing HDF5 external refs and Jinja2 templating.
  - `rule_9/` (Somay): Biscuit-token identity attenuation and Min-Cut IAM graph verification.
- `validation/`: Scripts to test our controls.
  - `replay_attack.py`: Deterministically replays the 17,600-action known attack path.
  - `adaptive_agent.py`: Uses an LLM to attempt alternative lateral movement in $N$ trials to measure survival rate.
- `report/`: The final 8-page draft, trust boundary figures, and the main control matrix table.

## Quickstart

1. `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and fill in necessary API keys.
3. Start the broken lab: `docker-compose -f environments/broken_lab/docker-compose.yml up`
4. Run the validation sequence: `python validation/replay_attack.py --target broken`

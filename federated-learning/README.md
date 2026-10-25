# Non-IID Label Swap Detector (HB-NIID-LSD)

Cleans an FL client's local training data **before** training, by removing rows whose label was swapped from an attack to `BENIGN`. That's the label-flipping / label-poisoning attack on federated learning.

Member 4 · Zero Trust Security for IoT using AI and Blockchain

## Files

| File | What it does |
|---|---|
| `niidlsd.py` | **The detector.** `learn` builds history from clean data, `detect` removes swapped rows |
| `attacker.py` | Simulates the attack: relabels 10% of attack rows as BENIGN and writes the answer key |
| `preprocessing/dataset_builder.py` | Adds the `device_type` column (from protocol; in production it comes from Member 3's registry) |
| `preprocessing/split.py` | Splits data into a **history half** (detector learns) and a **client round** (gets poisoned) |
| `experiments/impact_autoencoder.py` | Retrains Member 2's Autoencoder on clean / poisoned / cleaned data and compares them |
| `preprocessing/m2_clean_dataset.py`, `m2_split_dataset.py` | Member 2's preprocessing, unchanged |
| `experiments/archive/` | Full-option research versions (sweep mode, flip rates, targeted attack) |
| `ruleset.json` | Layer 1 rules (written automatically if missing) |

All settings are named constants at the top of `niidlsd.py` and `attacker.py`.
**Run every command from inside this folder** — all paths are relative to it.

```bash
pip install -r requirements.txt
```

## Run it

```bash
# Once: Member 2's preprocessing (Kaggle CICIoT2023 train.csv in datasets/raw/)
python preprocessing/m2_clean_dataset.py
python preprocessing/m2_split_dataset.py
python preprocessing/dataset_builder.py --input datasets/processed/splits/train.csv --output data/train_devices.csv
python preprocessing/split.py --input data/train_devices.csv --test-size 0.5 --seed 42 --outdir data
#   → data/train.csv (history half)   data/test.csv (client round)

# The demo — learn on the history half, attack + clean the client round
python niidlsd.py --mode learn  --input data/train.csv                                # 1. learn what's normal
python attacker.py --input data/test.csv --output data/poisoned.csv                   # 2. attacker swaps labels
python niidlsd.py --mode detect --input data/poisoned.csv --output data/cleaned.csv   # 3. detect + grade itself

# Impact on Member 2's model
python experiments/impact_autoencoder.py --train clean=data/test.csv --train poisoned=data/poisoned.csv \
       --train cleaned=data/cleaned.csv --eval datasets/processed/splits/validation.csv --out results/impact
```

## How a BENIGN-labelled row is judged

| Layer | Question | Source |
|---|---|---|
| 1. Ruleset | Is this protocol ever benign on this device type? | `ruleset.json` |
| 2. History | Was this device+protocol ≥90% attack before? → **suspicious** | `history/label_history.json` |
| 3. Statistics | How far is the row from this device's real benign traffic? (log scale, median/MAD) | `history/benign_profiles.json` |

**A row is removed if:** Layer 1 fires · **or** it's a normal row with ≥2 features at robust Z > 3.5 · **or** it's a suspicious row with ≥1 feature at Z > 2.0 · **or** it's suspicious on a device with no benign profile. Unknown devices are checked against a profile pooled over all benign traffic.

**Why median/MAD on a log scale?** A few real benign rows have extreme values (Rate up to 8.4M, IAT up to 1.7e8). With mean/std they stretch "normal" until attacks fit inside it (recall fell to 22.6%). The median ignores extremes, and the log scale stops real outliers looking crazy.

**Why does Layer 1 catch nothing on CICIoT2023?** Device type is derived from protocol here, so "camera + SSH" can't occur, and its rule protocols (Telnet, IRC) are always 0 in this dataset. In production, device type comes from Member 3's IP registry, independent of protocol.

## Results (Member 2's data, client round 1,873,786 rows, 182,953 swaps)

| | |
|---|---|
| Swaps caught (recall) | **99.7%** (571 missed) |
| Precision | 90.7% |
| Real benign kept | 57.9% |

Member 2's Autoencoder retrained on each set, tested on his validation split:

| Trained on | ROC AUC | Attacks caught at 5% false alarms |
|---|---|---|
| clean | 0.973 | 92.2% |
| poisoned | **0.060** | 1.2% |
| cleaned by the detector | **0.950** | 51.1% |

**About 97% of the damage to the model's ranking ability is undone.** The remaining gap is mostly SYN floods.

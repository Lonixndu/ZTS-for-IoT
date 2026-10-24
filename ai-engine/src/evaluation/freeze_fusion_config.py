
from pathlib import Path
import json
import pandas as pd

results_dir = Path("results/fusion_v2")

df = pd.read_csv(
    results_dir / "matched_fpr_comparison.csv"
)

metadata = json.loads(
    (results_dir / "experiment_metadata.json")
    .read_text(encoding="utf-8")
)

def get_candidate(name):
    rows = df[
        (df["model"] == name)
        & (df["target_fpr"].round(6) == 0.04)
    ]

    if len(rows) != 1:
        raise ValueError(
            f"Expected one candidate for {name}"
        )

    return rows.iloc[0]

xgb = get_candidate("XGBoost only")
fusion = get_candidate("XGBoost 80% + AE 20%")

config = {
    "version": "fusion_v2_frozen",
    "selection_dataset": "validation",
    "target_benign_fpr": 0.04,
    "ae_normalization": {
        "method": "clip(error / scale, 0, 1)",
        "scale": float(metadata["ae_scale"])
    },
    "candidates": {
        "xgboost_only": {
            "xgb_weight": 1.0,
            "ae_weight": 0.0,
            "threshold": float(xgb["threshold"])
        },
        "xgboost_ae_fusion": {
            "xgb_weight": 0.8,
            "ae_weight": 0.2,
            "threshold": float(fusion["threshold"])
        }
    }
}

output = results_dir / "frozen_config.json"

output.write_text(
    json.dumps(config, indent=4),
    encoding="utf-8"
)

print("Frozen configuration saved:", output)
print(json.dumps(config, indent=4))

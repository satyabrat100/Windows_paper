# detector_eval.py — context-conditioned detector of ASEP registry writes.
# Reproduces the paper's detector evaluation: random vs host-disjoint split
# (Table 7) and operating points under host-disjoint CV (Table 8).
#
# Label: positive = write lands on a recognised ASEP class; negative = other.
# Features are CONTEXT only (writer, value, host-local rarity) — the ASEP key
# itself is NOT a feature, so the model cannot trivially memorise the label.
#
# Usage:  py detector_eval.py

import re
import sys
import math
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupKFold, KFold
from sklearn.metrics import roc_auc_score

CSV = "registry_events.csv"

ASEP = [
    r"\\CurrentControlSet\\Services\\", r"\\ControlSet\d+\\Services\\",
    r"\\Schedule\\TaskCache\\", r"\\SystemCertificates\\Root\\Certificates\\",
    r"\\CurrentVersion\\Run(Once)?\\", r"\\shell\\open\\command",
    r"\\shell\\[^\\]+\\command",
    r"\\Winlogon\\(Shell|Userinit|Notify|GinaDLL|Taskman)",
    r"\\Control\\Print\\(Monitors|Environments|Providers)\\",
    r"\\Image File Execution Options\\",
    r"\\CLSID\\.*\\(InprocServer32|LocalServer32|TreatAs)",
    r"ShellIconOverlayIdentifiers", r"\\shellex\\",
    r"\\Office\\.*\\(Addins|Options)", r"\\Active Setup\\Installed Components\\",
    r"\\StartupApproved\\", r"\\Netsh\\", r"AppInit_DLLs|AppCertDlls",
    r"\\Lsa\\(Security Packages|Authentication Packages)",
    r"\\AppCompatFlags\\(Custom|InstalledSDB)\\",
    r"\\Cryptography\\(Providers\\Trust|OID)\\",
]
ASEP_RX = re.compile("|".join(ASEP), re.IGNORECASE)
LOLBINS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
           "regsvr32", "reg.exe", "schtasks", "sc.exe", "cscript", "msiexec",
           "installutil", "regasm", "wmic", "certutil")
USERWRITE = ("\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\",
             "\\public\\", "\\downloads\\")


def has(s, subs):
    s = (s or "").lower()
    return int(any(x in s for x in subs))


def main():
    try:
        df = pd.read_csv(CSV, dtype=str, keep_default_na=False)
    except FileNotFoundError:
        print(f"{CSV} not found. Run extract_all.py first.")
        sys.exit(1)

    print(f"Loaded {len(df)} events")
    df["y"] = df["target_object"].map(
        lambda t: int(bool(ASEP_RX.search(t))) if isinstance(t, str) else 0)
    base = df["y"].mean()
    print(f"Base rate (positives): {base:.4f}  ({df['y'].sum()} of {len(df)})")

    img = df["process_image"].fillna("").str.lower()
    det = df["details"].fillna("")
    # frequency features
    gfreq = img.map(img.value_counts()).astype(float)
    hostimg = (df["host"].fillna("") + "|" + img)
    hfreq = hostimg.map(hostimg.value_counts()).astype(float)

    X = pd.DataFrame({
        "event_id": pd.to_numeric(df["event_id"], errors="coerce").fillna(13),
        "proc_system": img.map(lambda s: has(s, ("\\system32\\", "\\syswow64\\"))),
        "proc_userwrite": img.map(lambda s: has(s, USERWRITE)),
        "proc_lolbin": img.map(lambda s: int(any(b in s for b in LOLBINS))),
        "det_len": det.str.len().clip(upper=500),
        "det_exedll": det.map(lambda s: has(s, (".exe", ".dll"))),
        "det_userwrite": det.map(lambda s: has(s, USERWRITE)),
        "det_interp": det.map(lambda s: has(s, ("powershell", "cmd", "-enc",
                                                "http", "rundll32", ".ps1"))),
        "user_system": df["user"].fillna("").str.lower().map(
            lambda s: int("system" in s or "nt authority" in s)),
        "writer_gfreq": np.log1p(gfreq),
        "writer_hfreq": np.log1p(hfreq),
    }).astype(float)
    y = df["y"].values
    groups = df["host"].fillna("unknown").values

    def oof_auc(splitter, split_args):
        pred = np.zeros(len(y))
        for tr, te in splitter.split(X, y, **split_args):
            m = HistGradientBoostingClassifier(max_iter=200, random_state=0)
            m.fit(X.iloc[tr], y[tr])
            pred[te] = m.predict_proba(X.iloc[te])[:, 1]
        return pred

    print("\n=== Table 7: effect of split strategy ===")
    # random 5-fold (leaky)
    pr_rand = oof_auc(KFold(5, shuffle=True, random_state=0), {})
    # host-grouped
    ngrp = len(set(groups))
    k = min(5, ngrp)
    pr_host = oof_auc(GroupKFold(k), {"groups": groups})
    for name, pr in [("Random 5-fold (leaky)", pr_rand),
                     ("Grouped by HOST (strict)", pr_host)]:
        print(f"  {name:28} ROC-AUC = {roc_auc_score(y, pr):.3f}")

    print("\n=== Table 8: operating points, host-disjoint CV ===")
    print(f"ROC-AUC (host-disjoint): {roc_auc_score(y, pr_host):.3f}")
    print(f"{'target recall':>14} {'precision':>10} {'alerts/10k':>12}")
    print("-" * 40)
    order = np.argsort(-pr_host)
    ys = y[order]
    P = y.sum()
    tp = np.cumsum(ys)
    fp = np.cumsum(1 - ys)
    recall = tp / P
    precision = tp / (tp + fp)
    alerts = (np.arange(1, len(y) + 1) / len(y)) * 10000
    for tr in (0.50, 0.70, 0.80, 0.90, 0.95):
        idx = np.searchsorted(recall, tr)
        idx = min(idx, len(y) - 1)
        print(f"{tr:14.2f} {precision[idx]:10.3f} {alerts[idx]:12.0f}")

    print("\nCompare with paper Table 8: AUC 0.891; precision 0.128 and "
          "~2908 alerts/10k at recall 0.90.")


if __name__ == "__main__":
    main()
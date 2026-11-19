# experiments.py — the three missing experiments for the registry paper:
#   A. baseline comparison (rules vs context detector), host-disjoint
#   B. feature-family ablation (leave-one-family-out)
#   C. leave-one-technique-out recall
#
# Usage:  py experiments.py

import re
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score

CSV = "registry_events.csv"

ASEP_CLASSES = {
    "Service": r"\\CurrentControlSet\\Services\\|\\ControlSet\d+\\Services\\",
    "ScheduledTask": r"\\Schedule\\TaskCache\\",
    "RootCert": r"\\SystemCertificates\\Root\\Certificates\\",
    "Run": r"\\CurrentVersion\\Run(Once)?\\",
    "ShellCommand": r"\\shell\\open\\command|\\shell\\[^\\]+\\command",
    "Winlogon": r"\\Winlogon\\(Shell|Userinit|Notify|GinaDLL|Taskman)",
    "PortMonitor": r"\\Control\\Print\\(Monitors|Environments|Providers)\\",
    "IFEO": r"\\Image File Execution Options\\",
    "COM": r"\\CLSID\\.*\\(InprocServer32|LocalServer32|TreatAs)",
    "ShellExt": r"ShellIconOverlayIdentifiers|\\shellex\\",
    "Office": r"\\Office\\.*\\(Addins|Options)",
    "ActiveSetup": r"\\Active Setup\\Installed Components\\",
    "StartupApproved": r"\\StartupApproved\\",
    "Netsh": r"\\Netsh\\",
    "AppInit": r"AppInit_DLLs|AppCertDlls",
    "LSA": r"\\Lsa\\(Security Packages|Authentication Packages)",
    "Shim": r"\\AppCompatFlags\\(Custom|InstalledSDB)\\",
    "SIP": r"\\Cryptography\\(Providers\\Trust|OID)\\",
}
COMPILED = {k: re.compile(v, re.IGNORECASE) for k, v in ASEP_CLASSES.items()}
HEAD = ("Service", "Run")
SIGMA = ("Service", "Run", "ScheduledTask", "Winlogon", "IFEO", "AppInit")
LOLBINS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
           "regsvr32", "reg.exe", "schtasks", "sc.exe", "msiexec", "certutil")
USERWRITE = ("\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\",
             "\\public\\", "\\downloads\\")


def classify(t):
    if not isinstance(t, str):
        return None
    for k, rx in COMPILED.items():
        if rx.search(t):
            return k
    return None


def has(s, subs):
    s = (s or "").lower()
    return int(any(x in s for x in subs))


def build(df):
    img = df["process_image"].fillna("").str.lower()
    det = df["details"].fillna("")
    gfreq = img.map(img.value_counts()).astype(float)
    hostimg = df["host"].fillna("") + "|" + img
    hfreq = hostimg.map(hostimg.value_counts()).astype(float)
    F1 = pd.DataFrame({  # writer identity
        "proc_system": img.map(lambda s: has(s, ("\\system32\\", "\\syswow64\\"))),
        "proc_userwrite": img.map(lambda s: has(s, USERWRITE)),
        "proc_lolbin": img.map(lambda s: int(any(b in s for b in LOLBINS))),
        "user_system": df["user"].fillna("").str.lower().map(
            lambda s: int("system" in s or "nt authority" in s)),
    })
    F2 = pd.DataFrame({  # written value
        "det_len": det.str.len().clip(upper=500),
        "det_exedll": det.map(lambda s: has(s, (".exe", ".dll"))),
        "det_userwrite": det.map(lambda s: has(s, USERWRITE)),
        "det_interp": det.map(lambda s: has(s, ("powershell", "cmd", "-enc",
                                                "http", "rundll32", ".ps1"))),
        "event_id": pd.to_numeric(df["event_id"], errors="coerce").fillna(13),
    })
    F4 = pd.DataFrame({  # host-local rarity
        "writer_gfreq": np.log1p(gfreq),
        "writer_hfreq": np.log1p(hfreq),
    })
    return {"F1": F1, "F2": F2, "F4": F4}


def main():
    try:
        df = pd.read_csv(CSV, dtype=str, keep_default_na=False)
    except FileNotFoundError:
        print(f"{CSV} not found. Run extract_all.py first.")
        sys.exit(1)

    print(f"Loaded {len(df)} events")
    df["cls"] = df["target_object"].map(classify)
    df["y"] = df["cls"].notna().astype(int)
    groups = df["host"].fillna("unknown").values
    fam = build(df)
    Xall = pd.concat(fam.values(), axis=1).astype(float)
    y = df["y"].values
    print(f"Base rate {y.mean():.4f}; positives {y.sum()}\n")

    def oof(X):
        pred = np.zeros(len(y))
        for tr, te in GroupKFold(5).split(X, y, groups=groups):
            m = HistGradientBoostingClassifier(max_iter=150, random_state=0)
            m.fit(X.iloc[tr], y[tr])
            pred[te] = m.predict_proba(X.iloc[te])[:, 1]
        return pred

    # ---------- A. baseline comparison ----------
    print("=== A. Baseline comparison (host-disjoint) ===")
    def rule_pred(kinds):
        return df["cls"].map(lambda c: int(c in kinds)).values

    def rule_path():  # path heuristic: user-writable target or interpreter value
        tgt = df["target_object"].fillna("").str.lower()
        det = df["details"].fillna("").str.lower()
        return ((tgt.map(lambda s: has(s, USERWRITE)) |
                 det.map(lambda s: has(s, ("powershell", "-enc", "rundll32",
                                           ".ps1", "appdata", "\\temp\\")))).astype(int)).values

    def rep_rule(name, pred):
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        rec = tp / y.sum()
        prec = tp / (tp + fp) if (tp + fp) else 0
        al = (pred == 1).sum() / len(y) * 10000
        print(f"  {name:26} recall={rec:.3f} precision={prec:.3f} "
              f"alerts/10k={al:7.0f}")

    rep_rule("B1 any-write head", rule_pred(HEAD))
    rep_rule("B2 Sigma-style subset", rule_pred(SIGMA))
    rep_rule("B3 path-heuristic", rule_path())
    pr = oof(Xall)
    auc = roc_auc_score(y, pr)
    order = np.argsort(-pr)
    ys = y[order]
    tp = np.cumsum(ys)
    fp = np.cumsum(1 - ys)
    rec = tp / y.sum()
    prec = tp / (tp + fp)
    al = np.arange(1, len(y) + 1) / len(y) * 10000
    i90 = min(np.searchsorted(rec, 0.90), len(y) - 1)
    print(f"  {'P proposed (context)':26} recall=0.900 "
          f"precision={prec[i90]:.3f} alerts/10k={al[i90]:7.0f}  (AUC {auc:.3f})")

    # ---------- B. feature-family ablation ----------
    print("\n=== B. Feature-family ablation (leave-one-out, host-disjoint AUC) ===")
    print(f"  {'full (F1+F2+F4)':24} AUC={auc:.3f}")
    for drop in ("F1", "F2", "F4"):
        keep = [k for k in fam if k != drop]
        Xd = pd.concat([fam[k] for k in keep], axis=1).astype(float)
        a = roc_auc_score(y, oof(Xd))
        print(f"  {'drop '+drop:24} AUC={a:.3f}   (dAUC {auc-a:+.3f})")
    print("  (F3 bounded-provenance not available in this extraction)")

    # ---------- C. leave-one-technique-out ----------
    print("\n=== C. Leave-one-technique-out recall ===")
    # threshold at ~1% global false-positive rate, from a model trained on all
    full_pred = pr
    neg_scores = np.sort(full_pred[y == 0])
    thr = neg_scores[int(0.99 * len(neg_scores))]
    print(f"  threshold at 1% FP = {thr:.3f}")
    print(f"  {'held-out technique':18} {'pos':>5} {'recall':>7}")
    counts = df[df["y"] == 1]["cls"].value_counts()
    for cls in counts.index:
        npos = int(counts[cls])
        if npos < 5:
            continue
        mask_train = ~((df["y"] == 1) & (df["cls"] == cls)).values
        m = HistGradientBoostingClassifier(max_iter=150, random_state=0)
        m.fit(Xall[mask_train], y[mask_train])
        test_idx = ((df["y"] == 1) & (df["cls"] == cls)).values
        sc = m.predict_proba(Xall[test_idx])[:, 1]
        rec = (sc >= thr).mean()
        print(f"  {cls:18} {npos:5d} {rec:7.3f}")


if __name__ == "__main__":
    main()
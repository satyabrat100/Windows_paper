# analyze2.py — tuned ASEP classification (Table 2), prevalence coverage curve,
# and baseline monitoring comparison by recall/coverage.
#
# Usage:  py analyze2.py

import re
import sys
import random
import pandas as pd

CSV = "registry_events.csv"
N_BOOT = 5000
random.seed(0)

# Tuned ASEP patterns. Changes from v1:
#  - Winlogon: broadened to all autostart values under the Winlogon key
#  - Root certificate: narrowed to the actual root-store install path
#  - Port monitor / print: added Providers and print-processor paths
ASEP_PATTERNS = [
    ("Service creation / modification", "T1543.003",
     r"\\CurrentControlSet\\Services\\|\\ControlSet\d+\\Services\\"),
    ("Scheduled task registration", "T1053.005",
     r"\\Schedule\\TaskCache\\"),
    ("Root certificate install", "T1553.004",
     r"\\SystemCertificates\\Root\\Certificates\\"),
    ("Run / RunOnce keys", "T1547.001",
     r"\\CurrentVersion\\Run(Once)?\\|\\CurrentVersion\\Run(Once)?$|"
     r"\\CurrentVersion\\RunServices(Once)?\\"),
    ("Shell open command hijack", "T1546.001",
     r"\\shell\\open\\command|\\shell\\[^\\]+\\command"),
    ("Winlogon Shell/Userinit/Notify", "T1547.004",
     r"\\Winlogon\\(Shell|Userinit|Notify|GinaDLL|Taskman|System|VmApplet|"
     r"AppSetup|UserInit|Shell Folders)|\\Winlogon\\Notify\\"),
    ("Port monitor / print driver", "T1547.010",
     r"\\Control\\Print\\(Monitors|Environments|Providers)\\|"
     r"\\Control\\Print\\.*\\Print Processors\\"),
    ("Image File Execution Options", "T1546.012",
     r"\\Image File Execution Options\\"),
    ("COM object hijack (CLSID)", "T1546.015",
     r"\\CLSID\\.*\\(InprocServer32|LocalServer32|TreatAs)"),
    ("Shell extension / ShellIconOverlay", "T1546",
     r"ShellIconOverlayIdentifiers|\\shellex\\"),
    ("Office add-in / template", "T1137",
     r"\\Office\\.*\\(Addins|Options|Resiliency)|\\Word\\.*\\Options"),
    ("Active Setup", "T1547.014",
     r"\\Active Setup\\Installed Components\\"),
    ("Explorer StartupApproved", "T1547.001",
     r"\\StartupApproved\\"),
    ("Netsh / LSA helper DLL", "T1546.007",
     r"\\Netsh\\"),
    ("AppInit_DLLs", "T1546.010",
     r"AppInit_DLLs|AppCertDlls"),
    ("LSA security packages / providers", "T1547.005",
     r"\\Lsa\\(Security Packages|Authentication Packages|OSConfig)"),
    ("Application shimming (SDB)", "T1546.011",
     r"\\AppCompatFlags\\(Custom|InstalledSDB)\\"),
    ("SIP / trust provider hijack", "T1553.003",
     r"\\Cryptography\\(Providers\\Trust|OID)\\"),
]
COMPILED = [(n, t, re.compile(p, re.IGNORECASE)) for n, t, p in ASEP_PATTERNS]


def classify(target):
    if not isinstance(target, str):
        return None
    for name, tid, rx in COMPILED:
        if rx.search(target):
            return name
    return None


def pctile(v, p):
    if not v:
        return 0.0
    v = sorted(v)
    return v[min(len(v) - 1, int(p * len(v)))]


def main():
    try:
        df = pd.read_csv(CSV, dtype=str, keep_default_na=False)
    except FileNotFoundError:
        print(f"{CSV} not found. Run extract_all.py first.")
        sys.exit(1)

    print(f"Loaded {len(df)} registry events")
    df["asep_class"] = df["target_object"].map(classify)
    hits = df[df["asep_class"].notna()].copy()
    print(f"  {len(hits)} events land on an ASEP class "
          f"({len(hits)/len(df)*100:.2f}% of all writes)\n")

    classes = [n for n, _, _ in ASEP_PATTERNS]
    sc = hits[["source_file", "asep_class"]].drop_duplicates()
    samples = sorted(sc["source_file"].unique())
    n_samples = len(samples)
    by_sample = sc.groupby("source_file")["asep_class"].apply(set).to_dict()
    pair_total = len(sc)
    counts = sc["asep_class"].value_counts().to_dict()
    w = {c: counts.get(c, 0) / pair_total for c in classes}

    boot = {c: [] for c in classes}
    slist = list(samples)
    for _ in range(N_BOOT):
        pick = [random.choice(slist) for _ in range(n_samples)]
        cc = {c: 0 for c in classes}
        pairs = 0
        for s in pick:
            for c in by_sample.get(s, ()):
                cc[c] += 1
                pairs += 1
        if pairs:
            for c in classes:
                boot[c].append(cc[c] / pairs)

    ev = hits["asep_class"].value_counts().to_dict()
    rows = []
    for c in classes:
        tid = next(t for n, t, _ in ASEP_PATTERNS if n == c)
        rows.append((c, tid, w[c], pctile(boot[c], .025), pctile(boot[c], .975),
                     counts.get(c, 0), ev.get(c, 0)))
    rows.sort(key=lambda r: r[2], reverse=True)

    print("=== Table 2: ASEP prevalence (tuned) ===")
    print(f"{'ASEP class':38} {'ATT&CK':11} {'w_a':>6} {'95% CI':>16} "
          f"{'Samp':>5} {'Events':>7}")
    print("-" * 90)
    for c, tid, wa, lo, hi, s, e in rows:
        print(f"{c:38} {tid:11} {wa:6.3f} [{lo:5.3f},{hi:5.3f}] {s:5d} {e:7d}")
    print(f"\n  {n_samples} attack samples, {pair_total} sample-class pairs\n")

    # === Coverage curve: monitor the top-B classes by prevalence ===
    # Coverage(B) = fraction of attack samples whose persistence is caught by
    # monitoring only the B highest-prevalence classes.
    ranked = [r[0] for r in rows]
    print("=== Coverage by head-only monitoring ===")
    print(f"{'Budget B':>8} {'classes monitored':40} {'% samples covered':>18}")
    print("-" * 70)
    for B in [1, 2, 3, 4, 5, 6, 8, 10]:
        mon = set(ranked[:B])
        covered = sum(1 for s in samples if by_sample.get(s, set()) & mon)
        print(f"{B:8d} {', '.join(ranked[:B])[:40]:40} "
              f"{covered/n_samples*100:17.1f}%")

    # === Baseline monitoring comparison (recall/coverage over ASEP writes) ===
    # Positive = a write on an ASEP class. Each baseline is a monitoring rule;
    # we report what fraction of ASEP writes (events) and attack samples it flags.
    def rule_head(cls):           # monitor only Service + Run keys
        return cls in ("Service creation / modification", "Run / RunOnce keys")

    def rule_sigma(cls):          # public-Sigma-style head + common tail keys
        return cls in ("Service creation / modification", "Run / RunOnce keys",
                       "Scheduled task registration", "Winlogon Shell/Userinit/Notify",
                       "Image File Execution Options", "AppInit_DLLs")

    def rule_full(cls):           # monitor every enumerated ASEP class
        return True

    print("\n=== Baseline monitoring comparison ===")
    print("Positive class = registry write on a recognised ASEP class "
          f"({len(hits)} events, {n_samples} samples).")
    print("Recall = share of ASEP writes a rule flags. Precision needs a benign")
    print("corpus and is not estimable on this attack-only data (see paper 9.5).\n")
    print(f"{'Baseline':28} {'ASEP events flagged':>20} {'recall(events)':>15} "
          f"{'samples covered':>16}")
    print("-" * 84)
    for name, rule in [("B1 head-only (Svc+Run)", rule_head),
                       ("B2 Sigma-style subset", rule_sigma),
                       ("B4 full ASEP monitoring", rule_full)]:
        flagged = hits[hits["asep_class"].map(rule)]
        rec = len(flagged) / len(hits)
        cov = sum(1 for s in samples
                  if any(rule(c) for c in by_sample.get(s, set())))
        print(f"{name:28} {len(flagged):20d} {rec:15.3f} "
              f"{cov}/{n_samples} ({cov/n_samples*100:.0f}%)")

    print("\nReading: head-only monitoring flags most EVENTS (service/Run are")
    print("noisy) yet misses attack samples that live only in the tail — the")
    print("coverage gap your allocation argument predicts.")


if __name__ == "__main__":
    main()
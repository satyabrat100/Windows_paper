# extract_all.py — build a registry-write CSV from BOTH .evtx and JSON datasets
# Reads Sysmon registry events (Event IDs 12, 13, 14) from every .evtx file and
# every .json / .jsonl / .ndjson / .zip file under the current folder.
#
# Usage:  py extract_all.py

import os
import csv
import sys
import json
import zipfile
import io
import xml.etree.ElementTree as ET

try:
    from Evtx.Evtx import Evtx
    HAVE_EVTX = True
except Exception:
    HAVE_EVTX = False

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
WANTED = {"12", "13", "14"}
ROOT = "."
OUT = "registry_events.csv"


def text(el):
    return el.text if el is not None and el.text is not None else ""


# ---------- .evtx parsing ----------
def parse_evtx_record(xml_str):
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None
    system = root.find(f"{NS}System")
    if system is None:
        return None
    eid = text(system.find(f"{NS}EventID"))
    if eid not in WANTED:
        return None
    computer = text(system.find(f"{NS}Computer"))
    fields = {}
    edata = root.find(f"{NS}EventData")
    if edata is not None:
        for d in edata.findall(f"{NS}Data"):
            fields[d.get("Name", "")] = text(d)
    return {
        "event_id": eid,
        "host": computer,
        "utc_time": fields.get("UtcTime", ""),
        "process_image": fields.get("Image", ""),
        "process_guid": fields.get("ProcessGuid", ""),
        "target_object": fields.get("TargetObject", ""),
        "details": fields.get("Details", ""),
        "user": fields.get("User", ""),
    }


# ---------- JSON parsing ----------
def get(d, *names):
    # case-insensitive lookup over several possible key names
    low = {k.lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in low and low[n.lower()] not in (None, ""):
            return low[n.lower()]
    return ""


def parse_json_obj(obj):
    if not isinstance(obj, dict):
        return None
    eid = str(get(obj, "EventID", "event_id", "EventId"))
    if eid not in WANTED:
        return None
    # only Sysmon registry events
    chan = str(get(obj, "Channel", "channel", "source_name")).lower()
    if chan and "sysmon" not in chan:
        return None
    return {
        "event_id": eid,
        "host": get(obj, "Hostname", "Computer", "host", "host_name"),
        "utc_time": get(obj, "UtcTime", "@timestamp", "TimeCreated", "utc_time"),
        "process_image": get(obj, "Image", "process_path", "image"),
        "process_guid": get(obj, "ProcessGuid", "process_guid"),
        "target_object": get(obj, "TargetObject", "target_object"),
        "details": get(obj, "Details", "details"),
        "user": get(obj, "User", "user", "SubjectUserName"),
    }


def iter_json_lines(fh):
    # yields parsed objects from a file handle that is either one JSON array,
    # one JSON object, or newline-delimited JSON (NDJSON)
    data = fh.read()
    if isinstance(data, bytes):
        data = data.decode("utf-8", "ignore")
    data = data.strip()
    if not data:
        return
    # try whole-file JSON first (array or object)
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            for o in parsed:
                yield o
        else:
            yield parsed
        return
    except json.JSONDecodeError:
        pass
    # fall back to NDJSON, line by line
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def main():
    evtx_files, json_files, zip_files = [], [], []
    for dirpath, _, filenames in os.walk(ROOT):
        for fn in filenames:
            low = fn.lower()
            full = os.path.join(dirpath, fn)
            if low.endswith(".evtx"):
                evtx_files.append(full)
            elif low.endswith((".json", ".jsonl", ".ndjson")):
                json_files.append(full)
            elif low.endswith(".zip"):
                zip_files.append(full)

    print(f"Found {len(evtx_files)} .evtx, {len(json_files)} json, "
          f"{len(zip_files)} zip files")

    rows = []

    # --- .evtx ---
    if HAVE_EVTX:
        for i, path in enumerate(evtx_files, 1):
            try:
                with Evtx(path) as log:
                    for rec in log.records():
                        r = parse_evtx_record(rec.xml())
                        if r:
                            r["source_file"] = os.path.relpath(path, ROOT)
                            rows.append(r)
            except Exception:
                pass
            if i % 100 == 0:
                print(f"  evtx {i}/{len(evtx_files)}, {len(rows)} reg events so far")

    # --- plain json ---
    for i, path in enumerate(json_files, 1):
        try:
            with open(path, "rb") as fh:
                for obj in iter_json_lines(fh):
                    r = parse_json_obj(obj)
                    if r:
                        r["source_file"] = os.path.relpath(path, ROOT)
                        rows.append(r)
        except Exception:
            pass
        if i % 20 == 0:
            print(f"  json {i}/{len(json_files)}, {len(rows)} reg events so far")

    # --- zip (read inner json/evtx-as-xml text) ---
    for i, path in enumerate(zip_files, 1):
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    low = name.lower()
                    if low.endswith((".json", ".jsonl", ".ndjson")):
                        with z.open(name) as fh:
                            for obj in iter_json_lines(fh):
                                r = parse_json_obj(obj)
                                if r:
                                    r["source_file"] = os.path.relpath(path, ROOT) + "::" + name
                                    rows.append(r)
        except Exception:
            pass
        if i % 20 == 0:
            print(f"  zip {i}/{len(zip_files)}, {len(rows)} reg events so far")

    if not rows:
        print("No registry events found in any format.")
        sys.exit(1)

    cols = ["event_id", "host", "utc_time", "process_image", "process_guid",
            "target_object", "details", "user", "source_file"]
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    hosts = {r["host"] for r in rows if r["host"]}
    procs = {r["process_image"] for r in rows if r["process_image"]}
    files = {r["source_file"] for r in rows}
    print()
    print(f"Done. Wrote {len(rows)} registry events to {OUT}")
    print(f"  distinct hosts:              {len(hosts)}")
    print(f"  distinct writing processes:  {len(procs)}")
    print(f"  source files (captures):     {len(files)}")


if __name__ == "__main__":
    main()
import argparse
from io import BytesIO
from json import dump
from pathlib import Path
from struct import unpack

import ifstools

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--contents", help="Contents folder", required=True)
parser.add_argument("-o", "--output", help="Json output", default="notecounts.json")
args = parser.parse_args()

sound_dir = Path(args.contents, "data", "sound")

if not sound_dir.is_dir():
    raise SystemExit(f"{sound_dir} does not exist")

all_charts = {}

chart_labels = {
    0: "SPH",
    1: "SPN",
    2: "SPA",
    3: "SPB",
    4: "SPL",
    6: "DPH",
    7: "DPN",
    8: "DPA",
    10: "DPL",
}


def load_chart_from_ifs(file):
    ifs = ifstools.IFS(file)
    dot_one = ifs.tree.all_files[-1].load()
    ifs.close()
    return dot_one


def get_notecounts(f, mid):
    print(mid)
    charts = {}
    for i in range(12):
        charts[i] = {}
        charts[i]["offset"], charts[i]["length"] = unpack("ii", f.read(8))

    all_charts[mid] = {}
    for i in charts:
        if i not in chart_labels:
            continue

        if charts[i]["offset"] == 0:
            all_charts[mid][chart_labels[i]] = 0
            continue

        f.seek(charts[i]["offset"])
        realcount = 0
        while True:
            offset, command, param, value = unpack("ibbh", f.read(8))
            if offset == 0x7FFFFFFF:
                break
            elif command in (0, 1):
                realcount += 2 if value != 0 else 1

        all_charts[mid][chart_labels[i]] = realcount


for dot_one in sound_dir.rglob("*.1"):
    mid = dot_one.stem
    # ifs takes priority
    if Path(sound_dir, f"{mid}.ifs").is_file():
        continue
    with open(dot_one, "r+b") as f:
        get_notecounts(f, mid)

for dot_ifs in sound_dir.glob("*.ifs"):
    mid = dot_ifs.stem
    # -p0 last
    if mid.endswith("-p0"):
        continue
    try:
        f = load_chart_from_ifs(dot_ifs)
    except OSError as e:
        print("ERROR:", e, dot_ifs)
        continue
    get_notecounts(BytesIO(f), mid)

for dot_ifs in sound_dir.glob("*-p0.ifs"):
    mid = dot_ifs.stem[:-3]
    try:
        f = load_chart_from_ifs(dot_ifs)
    except OSError as e:
        print("ERROR", e, dot_ifs)
        continue
    get_notecounts(BytesIO(f), mid)

with open(Path(args.output), "w") as fp:
    dump(all_charts, fp, sort_keys=True, indent=4)

print()
print(f"{len(all_charts)} {args.output}")

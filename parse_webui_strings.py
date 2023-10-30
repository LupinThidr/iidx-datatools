import json
import mmap
import re
from struct import pack, unpack

import pefile


def pos():
    return mm.tell()


def find_pattern(pattern, offset=0, adjust=0):
    if type(pattern) == str:
        return mm.seek(mm.find(bytes.fromhex(pattern), offset) + adjust)
    elif type(pattern) == bytes:
        return mm.seek(re.search(pattern, mm[offset:]).start() + offset + adjust)


with open("bm2dx.dll", "r+b") as bm2dx:
    mm = mmap.mmap(bm2dx.fileno(), length=0, access=mmap.ACCESS_READ)
    pe = pefile.PE("bm2dx.dll", fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    settings = {}
    settings_names = (
        "NOTES",
        "FRAME",
        "EXPLOSION",
        "TURNTABLE",
        "FULLCOMBO",
        "KEYBEAM",
        "JUDGESTRING",
        "LANECOVER",
        # "GRAPHAREA",
        "CATEGORYVOICE",
        "MUSICSELECTBGM",
        # "RIVALWINDOW",
        # "SOUNDPREVIEW",
        # "GRAPH CUTIN",
        "KOKOKARA START",
    )

    print("settings:")
    for name in settings_names:
        settings[name] = []
        find_name = f"{name:<15}:"
        find_pattern(str.encode(find_name).hex())
        find_pattern(pack("q", pe.get_rva_from_offset(pos()) + base).hex(), 0, 8)
        count = int(unpack("q", mm.read(8))[0])
        mm.seek(pe.get_offset_from_rva(unpack("q", mm.read(8))[0] - base))
        for i in range(count):
            addr = unpack("q", mm.read(8))[0] - base
            settings[name].append(pe.get_string_at_rva(addr).decode("cp932"))
        print(f"  {name.lower()}:", count)

    with open("settings.json", "w", newline="\n", encoding="utf-8") as fp:
        json.dump(settings, fp, indent=4, ensure_ascii=False)

    sd9_names = {}
    find_pattern(str.encode("ID SORT").hex())
    find_pattern(
        rb"\x01\x00\x00\x00....\x01\x00\x00\x00....\x01\x00\x00\x00", pos(), -4
    )
    mm.seek(pos())
    count = 0
    while True:
        try:
            start = pos()

            str_addr = unpack("q", mm.read(8))[0] - base
            sd9_addr = unpack("q", mm.read(8))[0] - base

            sd9_title = pe.get_string_at_rva(sd9_addr).decode("cp932")
            str_title = pe.get_string_at_rva(str_addr).decode("cp932")

            sd9_names[sd9_title] = str_title

            mm.seek(start + 0x288)
        except UnicodeDecodeError:
            sd9_names.pop("", ".")
            break
        count += 1

    with open("sd9.json", "w", newline="\n", encoding="utf-8") as fp:
        json.dump(sd9_names, fp, indent=4, ensure_ascii=False)
        print("sd9:", count)

    qpro_names = {}
    parts = ("head", "hair", "face", "hand", "body")
    for part in parts:
        qpro_names[part] = {}
    find_pattern(str.encode("A-SCR").hex())
    find_pattern(
        rb"\x01\x00\x00\x00....\x01\x00\x00\x00....\x01\x00\x00\x00", pos(), -4
    )
    mm.seek(pos())
    count = 0
    while True:
        try:
            start = pos()

            ifs_addr = unpack("q", mm.read(8))[0] - base
            str_addr = unpack("q", mm.read(8))[0] - base

            ifs_title = pe.get_string_at_rva(ifs_addr).decode("cp932")[:-4]
            str_title = pe.get_string_at_rva(str_addr).decode("cp932")[4:]

            for part in parts:
                if ifs_title.endswith(f"_{part}"):
                    qpro_names[part][ifs_title] = str_title
                elif ifs_title.endswith(f"_{part}1"):
                    qpro_names[part][ifs_title] = str_title
                elif ifs_title.endswith(f"_{part}2"):
                    qpro_names[part][ifs_title] = str_title

            mm.seek(start + 0x10)
        except UnicodeDecodeError:
            qpro_names.pop("", ".")
            break
        # fix: loops >7000 times when the result is <2000
        count += 1

    with open("qpro.json", "w", newline="\n", encoding="utf-8") as fp:
        json.dump(qpro_names, fp, indent=4, ensure_ascii=False)
        print("qpro:")
        for p in parts:
            print(f"  {p}:", len(qpro_names[p]))

    region_names = {}
    find_pattern("53 54 41 47 45 20 48 4F 57 54 4F")
    find_pattern("3C 00 00 00", pos())
    start = pos()
    mm.seek(start)
    if int(unpack("q", mm.read(8))[0]) == 0:
        pass
    else:
        mm.seek(start)
    count = int(unpack("q", mm.read(8))[0])

    for _ in range(count):
        ja_addr = unpack("q", mm.read(8))[0] - base
        en_addr = unpack("q", mm.read(8))[0] - base
        idx = int(unpack("q", mm.read(8))[0])

        if idx == 0:
            en_addr = ja_addr

        if idx > 100:
            k, last_value = _, region_names[k] = region_names.popitem()
            idx = k + 1

        ja_title = pe.get_string_at_rva(ja_addr).decode("cp932")
        en_title = pe.get_string_at_rva(en_addr).decode("cp932")

        region_names[idx] = {}
        region_names[idx]["ja"] = ja_title
        region_names[idx]["en"] = en_title[3:].title().replace("_", " ")

    with open("region.json", "w", newline="\n", encoding="utf-8") as fp:
        json.dump(region_names, fp, indent=4, ensure_ascii=False)
        print("region:", count)

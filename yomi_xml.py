# import jaconv
import lxml.etree as ET

import musicdata_tool


def process(video_list, title_yomi, artist_yomi, omni_bin):
    omni_songs = musicdata_tool.extract_file(omni_bin, None, True)["data"]

    def yomi_merge(tree, root, conv_string, file):
        for i in omni_songs:
            data = ET.SubElement(root, "data")
            idx = ET.SubElement(data, "index")
            idx.text = str(i["song_id"])
            idx.set("__type", "s32")
            ymi = ET.SubElement(data, "yomi")
            ymi.text = "オムニミックス"
            # ymi.text = jaconv.alphabet2kata(i[conv_string].replace("\\", ""))
            ymi.set("__type", "str")
        root[:] = sorted(
            root,
            key=lambda child: (child.tag, int(child.find("index").text)),
            reverse=True,
        )
        tree.write(
            file.replace("yomi", "omni"),
            encoding="Shift-JIS",
            xml_declaration=False,
            pretty_print=True,
            doctype='<?xml version="1.0" encoding="Shift-JIS"?>',
        )

    yomi_parser = ET.XMLParser(encoding="Shift-JIS", remove_blank_text=True)

    title_tree = ET.parse(title_yomi, yomi_parser)
    title_root = title_tree.getroot()
    yomi_merge(title_tree, title_root, "title_ascii", title_yomi)

    artist_tree = ET.parse(artist_yomi, yomi_parser)
    artist_root = artist_tree.getroot()
    yomi_merge(artist_tree, artist_root, "artist", artist_yomi)

    video_parser = ET.XMLParser(encoding="utf-8", remove_blank_text=True)

    video_tree = ET.parse(video_list, video_parser)
    video_root = video_tree.getroot()

    for i in omni_songs:
        msc = ET.SubElement(video_root, "music")
        msc.set("id", str(i["song_id"]))
        info = ET.SubElement(msc, "info")
        ET.SubElement(info, "title_name").text = i["title"].replace("\\", "")
        ET.SubElement(info, "artist_name").text = i["artist"].replace("\\", "")
        ET.SubElement(info, "play_video_flags").text = "6"

    video_root[:] = sorted(
        video_root,
        key=lambda child: (child.tag, int(child.get("id"))),
        reverse=True,
    )
    for flag in video_tree.findall("music/info/play_video_flags"):
        flag.text = "6"
    video_tree.write(
        video_list.replace("list", "omni"),
        encoding="UTF-8",
        pretty_print=True,
        doctype='<?xml version="1.0" encoding="UTF-8"?>',
    )

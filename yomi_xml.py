import musicdata_tool
#import jaconv

import lxml.etree as ET
parser = ET.XMLParser(remove_blank_text=True)


def process(video_list, title_yomi, artist_yomi, omni_bin):
    tree = ET.parse(video_list, parser)
    root = tree.getroot()

    song_info = {}
    for song in musicdata_tool.extract_file(omni_bin, None, True).get('data', []):
        mid = song['song_id']

        song_info[mid] = {
            'artist': song['artist'],
            'title': song['title'],
            'title_ascii': song['title_ascii'],
            'volume': song['volume'],
            'genre': song['genre'],
            'game_version': song['game_version'],
            'mid': mid,
        }

    orig = []
    for music in root.findall('music'):

        attributes = music.attrib
        mid = attributes.get('id')

        for info in music.findall('info'):
            title = info.find('title_name').text
            artist = info.find('artist_name').text
            flag = info.find('play_video_flags').text
            orig.append(int(mid))


    for omni_id in song_info:
        if omni_id not in orig:
            msc = ET.SubElement(root, 'music')
            msc.set('id', str(omni_id))
            info = ET.SubElement(msc, 'info')
            titlename = ET.SubElement(info, 'title_name')
            titlename.text = song_info.get(int(omni_id), None)['title'].replace("\\", "")
            artistname = ET.SubElement(info, 'artist_name')
            artistname.text = song_info.get(int(omni_id), None)['artist'].replace("\\", "")
            playvideo = ET.SubElement(info, 'play_video_flags')
            playvideo.text = '6'
    root[:] = sorted(root, key=lambda child: (child.tag,int(child.get('id'))), reverse=True)
    flag = tree.findall('music/info/play_video_flags')
    for v in flag:
        v.text = '6'
    tree.write(video_list.replace("list", "omni"), encoding="UTF-8", pretty_print=True, doctype='<?xml version="1.0" encoding="UTF-8"?>')


    tree = ET.parse(title_yomi, parser)
    root = tree.getroot()

    for omni_id in song_info:
        if omni_id not in orig:
            data = ET.SubElement(root,"data")
            idx = ET.SubElement(data,"index")
            idx.text = str(omni_id)
            idx.set('__type', 's32')
            ymi = ET.SubElement(data,"yomi")
            ymi.text = str("オムニミックス")
    #        ymi.text = jaconv.alphabet2kata(song_info.get(int(omni_id), None)['title_ascii'].replace("\\", ""))
            ymi.set('__type', 'str')
    root[:] = sorted(root, key=lambda child: (child.tag,int(child.find('index').text)), reverse=True)
    tree.write(title_yomi.replace("yomi", "omni"), encoding="Shift-JIS", xml_declaration=False, pretty_print=True, doctype='<?xml version="1.0" encoding="Shift-JIS"?>')


    tree = ET.parse(artist_yomi, parser)
    root = tree.getroot()

    for omni_id in song_info:
        if omni_id not in orig:
            data = ET.SubElement(root,"data")
            idx = ET.SubElement(data,"index")
            idx.text = str(omni_id)
            idx.set('__type', 's32')
            ymi = ET.SubElement(data,"yomi")
            ymi.text = str("オムニミックス")
    #        ymi.text = jaconv.alphabet2kata(song_info.get(int(omni_id), None)['artist'].replace("\\", ""))
            ymi.set('__type', 'str')
    root[:] = sorted(root, key=lambda child: (child.tag,int(child.find('index').text)), reverse=True)
    tree.write(artist_yomi.replace("yomi", "omni"), encoding="Shift-JIS", xml_declaration=False, pretty_print=True, doctype='<?xml version="1.0" encoding="Shift-JIS"?>')

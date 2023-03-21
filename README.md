# beatmania IIDX omnimix converter/creator

## Supported Versions
- 27 HEROIC VERSE
- 28 BISTROVER
- 29 CastHour
- 30 RESIDENT

*Standalone `musicdata_tool.py` supports IIDX 20<->30+

Thanks to WF for the original musicdata_tool and create_texturelist.


## Usage
1. `pip install -U -r requirements.txt`
2. Copy required files to this root directory: (WARNING: deleted when done!)
- (NEW VERSION BASE `bm2dx.dll`, `mdata.ifs`, `music_artist_yomi.xml`, `music_data.bin`, `music_title_yomi.xml`, `video_music_list.xml`)
- (OLD VERSION OMNI `mdato.ifs`, `music_omni.bin`)
3. Run `python build_omnimix.py`
4. Copy the resulting output/`data` to game contents
- mempatch_hook `iidx_omnimix_??.txt` is deprecated, use [BemaniPatcher](https://github.com/drmext/BemaniPatcher/tree/master/docs)
5. Copy dummied sound and movie files from old base data

## Extra
`parse_webui_strings.py` outputs debug info in bm2dx.dll to json

- qpro part real titles
- sd9 system sound real titles
- region names (Japanese and truncated English)
- setting names (notes, frame, explosion, turntable, fullcombo, keybeam, judgestring, lanecover, categoryvoice, musicselectbgm, kokokara start)

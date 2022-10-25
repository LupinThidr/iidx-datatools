# beatmania IIDX 27 to 28 to 29 to 30 omnimix converter/creator

Automatically convert between HEROIC VERSE, BISTROVER, CastHour, and RESIDENT Omnimix.

Thanks to WF for the original musicdata_tool and create_texturelist.


## USAGE:
1. `pip install -U -r requirements.txt`
2. Copy the required files to this root directory: (WARNING: they will be deleted when done!)
- (NEW VERSION BASE `bm2dx.dll`, `mdata.ifs`, `music_artist_yomi.xml`, `music_data.bin`, `music_title_yomi.xml`, `video_music_list.xml`)
- (OLD VERSION OMNI `mdato.ifs`, `music_omni.bin`) from hv_omnimix/ or omnimix_1.28.1/
3. Run `python3 build_omnimix.py`
4. Copy the resulting output/`data` and `iidx_omnimix_29.txt` to your game contents
5. Copy dummied sound and movie files from old base data
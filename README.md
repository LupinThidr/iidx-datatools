# beatmania IIDX 27 to 28 omnimix converter/creator

Automatically convert Heroic Verse Omnimix to Bistrover Omnimix.

Thanks to WF for the original musicdata_tool and create_texturelist.


## USAGE:
1. `pip install -U -r requirements.txt`
2. Copy the required files to this root directory: (WARNING: they will be deleted when done!)
- (NEW VERSION BASE `bm2dx.dll`, `mdata.ifs`, `music_artist_yomi.xml`, `music_data.bin`, `music_title_yomi.xml`, `video_music_list.xml`)
- (OLD VERSION OMNI `mdato.ifs`, `music_omni.bin`) from hv_omnimix/
3. Run `python3 build_omnimix.py`
4. Copy the resulting output/`data` and `iidx_omnimix_28.txt` to your 27orig+27omni+28orig folder
5. Copy (overwrite) the following dummied files from clean Rootage or HV base to your 27orig+27omni+28orig folder:
- `08024-p0.ifs` `15008-p0.ifs` `15012.ifs` `16011-p0.ifs` `16030-p0.ifs` `25065/` `26061/` to `out/data/sound`
- `25065.wmv` `26061.wmv` to `out/data/movie`

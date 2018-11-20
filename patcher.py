import argparse
import glob
import io
import os
import pathlib
import shutil
import sys
import tempfile

from ifstools.ifs import IFS

import musicdata_tool
from create_texturelist import create_texturelist


# Store temporary files and folders to be cleaned up after the process is finished
temp_filenames = []
temp_foldernames = []


def mkdtemp(prefix=None):
    foldername = tempfile.mkdtemp(prefix=prefix)
    #print("Made temp folder", foldername)
    temp_foldernames.append(foldername)
    return foldername


def tmpcleanup():
    for filename in temp_filenames:
        if os.path.exists(filename):
            #print("Removing temp file", filename)
            os.remove(filename)

    for foldername in temp_foldernames:
        if os.path.exists(foldername):
            #print("Removing temp folder", foldername)
            shutil.rmtree(foldername)


def extract_ifs(filename, path=None, silent=False):
    if not path:
        path = mkdtemp(prefix="ifs")

    # "progress" flag doesn't work properly.
    # It will still show the tqdm progress bar, just without
    # listing what files are being extracted.
    # To get around this, temporarily redirect stderr.
    # os.devnull doesn't work for this case, so use StringIO.

    if silent:
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()

    IFS(filename).extract(progress=False, path=path)

    if silent:
        sys.stderr = old_stderr

    # Get file list
    return glob.glob(os.path.join(path, "*")), path


def create_ifs(foldername, output_filename, silent=False):
    if silent:
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()

    IFS(foldername).repack(progress=False, path=output_filename)

    if silent:
        sys.stderr = old_stderr

    return output_filename


def find_files_in_path(path):
    files = {
        'mdata': None,
        'music_data': None,
    }

    for filename in glob.glob(path + "/**/*", recursive=True):
        if os.path.basename(filename) == "mdata.ifs":
            files['mdata'] = filename

        elif os.path.basename(filename) in ["music_data.bin", "music_omni.bin"]:
            files['music_data'] = filename

    if files['mdata'] is None:
        print("Couldn't find mdata.ifs in", path)
        exit(1)
    elif files['music_data'] is None:
        print("Couldn't find music_data.bin or music_omni.bin in", path)
        exit(1)

    return files


def get_output_path(input, output, replace):
    p = pathlib.Path(input)
    index = p.parts.index(replace) + 1
    return str(pathlib.Path(output).joinpath(*p.parts[index:]))


def merge_music_data(file_a, file_b, output):
    musicdata_tool.merge_files(file_a, file_b, output)


def merge_mdata(file_base, file_merge, output):
    _, base_mdata_path = extract_ifs(file_base)
    _, merge_mdata_path = extract_ifs(file_merge)

    base_mdata_files = set([x.replace(base_mdata_path + '/', '') for x in glob.glob(base_mdata_path + "/tex/*.png")])
    merge_mdata_files = set([x.replace(merge_mdata_path + '/', '') for x in glob.glob(merge_mdata_path + "/tex/*.png")])
    new_mdata_files = list(merge_mdata_files - base_mdata_files)

    # Copy images from other mdata/tex that don't exist into base mdata/tex
    for new_file in new_mdata_files:
        input_file = os.path.join(merge_mdata_path, new_file)
        output_file = os.path.join(base_mdata_path, new_file)

        if os.path.exists(output_file):
            os.unlink(output_file)

        shutil.copy(input_file, output_file)

    # Clear cache
    cache_path = os.path.join(base_mdata_path, "tex", "_cache")
    if os.path.exists(cache_path):
        shutil.rmtree(cache_path)

    # Remove old texturelist.xml
    texturelist_path = os.path.join(base_mdata_path, "tex", "texturelist.xml")
    if os.path.exists(texturelist_path):
        os.unlink(texturelist_path)

    # Generate new texturelist.xml
    create_texturelist(os.path.join(base_mdata_path, "tex"), texturelist_path)

    # Create actual IFS archive now, letting ifstools handle caches and such
    create_ifs(base_mdata_path, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-folder', help='Input base folder', default='base')
    parser.add_argument('--other-folder', help='Input data to merge into base', default='other')
    parser.add_argument('--output-folder', help='Output folder', default='output')

    args = parser.parse_args()

    if not os.path.exists(args.base_folder):
        print("Couldn't find base folder")

    if not os.path.exists(args.other_folder):
        print("Couldn't find data folder")

    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)

    # Find required files
    base_files = find_files_in_path(args.base_folder)
    other_files = find_files_in_path(args.other_folder)

    # Create patch file paths based on base_files
    patch_files = {
        'mdata': get_output_path(base_files['mdata'], args.output_folder, args.base_folder),
        'music_data': get_output_path(base_files['music_data'], args.output_folder, args.base_folder),
    }

    merge_music_data(other_files['music_data'], base_files['music_data'], patch_files['music_data'])
    merge_mdata(base_files['mdata'], other_files['mdata'], patch_files['mdata'])

    tmpcleanup()

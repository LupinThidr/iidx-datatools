import shutil
import sys
import os
import glob
import struct

files = sorted(glob.glob("*.2dx"))

for file in files:
    with open(file, "rb") as infile:
        infile.seek(0x14)
        file_count = struct.unpack("<I", infile.read(4))[0] // 2

        infile.seek(0x48)

        file_info = []
        for i in range(0, file_count):
            infile.seek(0x48 + (i * 8))

            offset, filesize = struct.unpack("<II", infile.read(8))

            infile.seek(offset + 0x2e)

            channels, sample_rate = struct.unpack("<HI", infile.read(6))

            if channels != 2 or sample_rate != 44100:
                print(file)
                shutil.copy(file, "output2")
                break


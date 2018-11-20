#!/bin/bash

if [ -d output ]; then
    rm -r output
fi

mkdir output

./2dx_extract $1
mv *.wav output

for filename in output/*.wav; do ffmpeg -i $filename -ar 44100 -ac 2 -b:a 192k -packet_size 8000 -y $(echo $filename | sed 's/wav/wma/g') && rm $filename; done

python3 create_s3p.py --input output --output $(echo $1 | sed 's/2dx/s3p/g')
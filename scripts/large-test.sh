#!/bin/bash

sk=../data/keys/large-sign.key
outf=large-sign.csv;

rm -f $outf

for f in $(ls ../data/sets/*); do
  echo -n "Processing file $f . . ."
  # Build a random policy of ands.
  p=`shuf -n 1 $f`
  for w in `shuf -n 3 $f`; do
    p=`echo "$p and $w"`
  done
  p=`echo "$p"`

  ctr=1;
  while [[ $ctr -le 1000 ]]; do
    tm=$(java -jar ../dist/rss.jar --sign large $sk $f "$p" | grep "Elapsed" | cut -d' ' -f3)
    #tm=$(java -jar ../dist/rss.jar --sign large $sk $f $p | grep "Elapsed" | cut -d' ' -f3)
    echo "$f;$tm" >> $outf
    ctr=$((ctr + 1))
  done
  echo " [ DONE ]"
done

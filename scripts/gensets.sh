#!/bin/sh

i=5
while [[ i -le  5000 ]];
  do
    for w in $(shuf -n $i /usr/share/dict/words); do
       echo $w | tr -d '-' >> ../data/sets/set$i
    done
    i=$((i + 5));
  done;

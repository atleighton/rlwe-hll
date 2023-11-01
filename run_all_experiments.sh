#!/bin/bash


for num_parties in 2 4 8
do
    for num_buckets in 128 256 512
    do
        ./run_experiments.sh 10000 10 $num_parties $num_buckets > res-$num_parties-$num_buckets.txt
    done
done

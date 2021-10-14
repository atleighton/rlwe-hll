#!/bin/bash

if [ "$1" == "-h" ]; then
  echo "Usage: `basename $0` \$NUM_PATIENTS \$NUM_CONDITIONS \$NUM_HOSPITALS \$NUM_BUCKETS"
  exit 0
fi

SKETCHES_DIR=$(pwd)/sim_sketches/

NUM_PATIENTS=${1:-100};
NUM_CONDITIONS=${2:-10};
NUM_HOSPITALS=${3:-8};
NUM_BUCKETS=${4:-4};

echo "Number of patients at each hospital: ${NUM_PATIENTS}";
echo "Number of conditions per patient: ${NUM_CONDITIONS}";
echo "Number of hospitals: ${NUM_HOSPITALS}";
echo "Number of hash buckets: ${NUM_BUCKETS}";


python generate_sim_data.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS;

python generate_loglog_sketches.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS --num_buckets $NUM_BUCKETS ;

mkdir build;
cd build;

cmake ..;
cd ..;
make;

python3 gen_cpp_code.py

#./combine-sketches
#./run_sim $NUM_PATIENTS $NUM_CONDITIONS $NUM_HOSPITALS $NUM_BUCKETS $SKETCHES_DIR
#./threshold-fhe-demo
./cpp_metacode $NUM_PATIENTS $NUM_CONDITIONS $NUM_HOSPITALS $NUM_BUCKETS $SKETCHES_DIR

python3 approximateCardinality.py --input_path $SKETCHES_DIR --num_buckets $NUM_BUCKETS
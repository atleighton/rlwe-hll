#!/bin/bash

if [ "$1" == "-h" ]; then
  echo "Usage: `basename $0` \$NUM_PATIENTS \$NUM_CONDITIONS \$NUM_HOSPITALS \$NUM_BUCKETS"
  exit 0
fi

SKETCHES_DIR=$(pwd)/sim_sketches/

NUM_PATIENTS=${1:-10000};
NUM_CONDITIONS=${2:-10};
NUM_HOSPITALS=${3:-2};
NUM_BUCKETS=${4:-128};

echo "Number of patients at each hospital: ${NUM_PATIENTS}";
echo "Number of conditions per patient: ${NUM_CONDITIONS}";
echo "Number of hospitals: ${NUM_HOSPITALS}";
echo "Number of hash buckets: ${NUM_BUCKETS}";

echo "Running gen_cpp_code.py to generate the appropriate C++ code":
python3 gen_cpp_code.py --num_hospitals $NUM_HOSPITALS --num_buckets $NUM_BUCKETS

echo "Running gen_sim_data.py to generate the simulated hospital data":
python3 generate_sim_data.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS;

echo "Running generate_loglog_sketches.py to generate simulated LogLog sketches":
python3 generate_loglog_sketches.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS --num_buckets $NUM_BUCKETS ;

mkdir -p build;
cd build;

cmake ..;
#cd ..;
make;


#./combine-sketches
#./run_sim $NUM_PATIENTS $NUM_CONDITIONS $NUM_HOSPITALS $NUM_BUCKETS $SKETCHES_DIR
#./threshold-fhe-demo
./cpp_metacode $NUM_PATIENTS $NUM_CONDITIONS $NUM_HOSPITALS $NUM_BUCKETS $SKETCHES_DIR

cd ..
python3 approximateCardinality.py --input_path $SKETCHES_DIR --num_buckets $NUM_BUCKETS

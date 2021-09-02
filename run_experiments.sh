NUM_PATIENTS=$1;
NUM_CONDITIONS=$2;
NUM_HOSPITALS=$3;
NUM_BUCKETS=$4;

echo "Number of patients at each hospital: ${NUM_PATIENTS}";
echo "Number of conditions per patient: ${NUM_CONDITIONS}";
echo "Number of hospitals: ${NUM_HOSPITALS}";
echo "Number of hash buckets: ${NUM_BUCKETS}";


python3 generate_sim_data.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS;

python generate_loglog_sketches.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS --num_buckets $NUM_BUCKETS ;


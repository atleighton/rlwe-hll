# rlwe-hll


## Instructions 1.1
General overview of system:
https://gitlab.com/palisade/palisade-release/blob/master/doc/palisade_manual.pdf

Some function documentation for one of the schemes:
https://palisade.gitlab.io/palisade-development/classlbcrypto_1_1LPSHEAlgorithm.html#a9b97098eb1ca1546361184260cc8795f

Compilation instructions for the example code, following
https://gitlab.com/palisade/palisade-development/-/wikis/Instructions-for-building-user-projects-that-use-PALISADE
```
mkdir build
cd build
cmake ..
make
./threshold-fhe-demo
```

## Instructions 1.2

Once PALISADE is up and running, compile code as shown here using cmake. To simulate protocol, run 

```
./run_experiments.sh ${NUM_PATIENTS} ${NUM_CONDITIONS} ${NUM_HOSPITALS} ${NUM_BUCKETS}
```

${NUM_PATIENTS} and ${NUM_CONDITIONS} are placeholder variables to simulate data. ${NUM_HOSPITALS} is the number of hospitals in the simulation, each with ${NUM_PATIENTS} patients. ${NUM_BUCKETS} is the number of sketch buckets. Default value is 4 parties with 64 buckets - this should run quickly. Increasing #buckets and #parties will increase compile time a lot and runtime a little. 

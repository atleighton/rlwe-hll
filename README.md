This code is associated with the following manuscript:
Alex Leighton and Yun William Yu; "Secure Federated Aggregate-Count Queries on Medical Patient Databases Using Fully-Homomorphic Cryptography". In submission.

## Requirements
* Palisade version 1.11 and dependencies:
  * cmake (Tested version 3.16.3)
  * autoconf (Tested version 2.69)
  * g++ (Tested version 9.3.0)
* Python version 3.8+ with packages:
  * scipy (Tested version 1.7.2)

On Ubuntu 20.04.3 LTS, Palisade can be installed as follows:
```
sudo apt install build-essential cmake autoconf
git clone https://gitlab.com/palisade/palisade-development.git
cd palisade-development
mkdir build
cd build
cmake ..
make
sudo make install
```
You may wish to do a parallel compilation with `make -j8`, and also testing that the build completed correctly `make testall`.

For full detail on Palisade instructions: https://gitlab.com/palisade/palisade-development/-/wikis/Instructions-for-building-PALISADE-in-Linux)

General overview of system:
https://gitlab.com/palisade/palisade-release/blob/master/doc/palisade_manual.pdf

## Quick-start simulation
Once PALISADE examples are up and running, to simulate protocol, in the rlwe-hll directory run

```
./run_experiments.sh ${NUM_PATIENTS} ${NUM_CONDITIONS} ${NUM_HOSPITALS} ${NUM_BUCKETS}
```
We note that it in our benchmarking prototype, we actually hardcode the number of parties and buckets into the C++ source by using Python to generate a C++ file to compile, in addition to using these parameters to generate the simulated data.
${NUM_PATIENTS} and ${NUM_CONDITIONS} are placeholder variables to simulate data; we use 10,000 and 10 respectively. ${NUM_HOSPITALS} is the number of hospitals in the simulation, each with ${NUM_PATIENTS} patients. ${NUM_BUCKETS} is the number of sketch buckets. Default value is 2 parties with 256 buckets - this should run quickly. Increasing #buckets and #parties will increase compile time a lot and runtime a little.
Note that the increase in compilation time is a side-effect of the simplified benchmarking procedure we use, and not inherent to the protocol; furthermore, it is of course entirely in preprocessing, so we did not bother optimizing it.

## More advanced instructions
The quick-start system is useful for getting up and running quickly, but you may find it necessary to manually edit and compile the code.


After cloning the repo,
```
git clone https://github.com/atleighton/rlwe-hll.git
cd rlwe-hll
```

First note that the actual C++ isn't included in the repo, but is instead generated by `gen_cpp_code.py`:
```
python3 gen_cpp_code.py --num_hospitals $NUM_HOSPITALS --num_buckets $NUM_BUCKETS
```
This manually unrolls the loops over both buckets and hospitals using a Python script into a C++ source file. As mentioned earlier, this is suboptimal for use in practice, and severely increases compilation time, but since this is all in preprocessing, we did not bother optimizing it. Because of the loop unrolling, we recommend using small parameter values while troubleshooting, such as the default of 2 hospitals and 128 buckets.

You may also wish to generate the simulated data, which we provided Python scripts for (see example files for format):
```
python3 generate_sim_data.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS;
python3 generate_loglog_sketches.py --num_patients $NUM_PATIENTS --num_conditions $NUM_CONDITIONS --num_hospitals $NUM_HOSPITALS --num_buckets $NUM_BUCKETS ;
```

Then we continue using the same build system as Palisade, based off of the example code in the Palisade package, with compilation instructions at
https://gitlab.com/palisade/palisade-development/-/wikis/Instructions-for-building-user-projects-that-use-PALISADE
```
mkdir -p build
cd build
cmake ..
make
./cpp_metacode $NUM_PATIENTS $NUM_CONDITIONS $NUM_HOSPITALS $NUM_BUCKETS $SKETCHES_DIR
python3 approximateCardinality.py --input_path $SKETCHES_DIR --num_buckets $NUM_BUCKETS
```


## Acknowledgment
We'd like to thank Yuriy Polyakov for his excellent webinars and tutorials at: https://gitlab.com/palisade/palisade-development/-/blob/master/src/pke/examples/

# rlwe-hll


## Instructions for ourselves (delete later)
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

Note that I copied out threshold-fhe.cpp because it is the one most similar to our use case.
It provides examples of doing basically vectorized count-mpc, which should be readily adaptable to our count-hll.

If you look at Table 2 of the PDF manual on page 14, that gives us the primitives that we have at our disposal.
I think that EvalAdd and its variants is sufficient for nearly everything we need because our protocol was
designed with ElGamal in mind originally.

### One possibility
After unrolling our HLL values into a unary format 3=[1,1,1,0,0,0,0,0], we then use element-wise addition
to take the max, resulting in something like 6=[4,3,3,1,1,1,0,0]. Then we somehow figure out how to count non-zers?

### Another possibility
We can use the opposite unary format 3=[0,0,0,1,1,1,1,1]. We then use element-wise multiplication to
take the max, resutling in something like 6=[0,0,0,0,0,0,1,1]. Then we subtract it all from 1, and then sum to get
6=sum([1,1,1,1,1,1,0,0]). This allows us to compute the bin values in the ciphertext, so we'll be left with the actual HLL sketch.

At that point, instead of using HLL, we can instead use just the ordinary LogLog algorithm:
http://algo.inria.fr/flajolet/Publications/DuFl03-LNCS.pdf / https://weishungchung.com/2014/07/30/hyperloglog/
Unlike HLL, which uses a harmonic mean, the original LogLog algorithm used just an arithmetic, mean, so we can just again sum up all the bin values.
Revealing the summed bin values let's use do basically everything in the CipherText, and all that is revealed at the end is a proxy for the estimate.
This way we also don't have to worry about any shuffling.

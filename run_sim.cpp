// @file  threshold-fhe.cpp - Examples of threshold FHE for BGVrns, BFVrns, and
// CKKS
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2020, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "palisade.h"
#include <iostream>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept> // std::runtime_error

using namespace std;
using namespace lbcrypto;


void RunHLLSketch(std::vector<std::vector<std::vector<int64_t>>> hospital_sketches, int num_hospitals, int num_buckets);
std::vector<std::vector<int64_t>> FetchSketches(int hospital_number);




int main(int argc, char *argv[]) {
  int num_patients= atoi(argv[1]);
  int num_conditions = atoi(argv[2]);
  int num_hospitals = atoi(argv[3]);
  int num_buckets = atoi(argv[4]);
  std::cout << num_patients << std::endl;
  std::cout << num_conditions << std::endl;
  std::cout << num_hospitals << std::endl;
  std::cout << num_buckets << std::endl;

  // load all sketches into 3d array. array[hospital number][bucket number] yields the unary sketch vector
  std::vector<std::vector<std::vector<int64_t>>> hospital_sketches;
  for (int hospital_number = 1; hospital_number <= num_hospitals; hospital_number++){
    hospital_sketches.push_back(FetchSketches(hospital_number));
  }


  std::cout << "\n=================RUNNING FOR HLL Sketches====================="
          << std::endl;

  RunHLLSketch(hospital_sketches, num_hospitals, num_buckets);

  return 0;
}



void RunHLLSketch(std::vector<std::vector<std::vector<int64_t>>> hospital_sketches, int num_hospitals, int num_buckets) {
  uint32_t plaintextModulus = 65537; //TODO ???
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic; // TODO ???
  uint32_t depth = ceil(log2(num_hospitals)); 
  //TODO sigma param???

  EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));
  usint batchSize = 1024;
  encodingParams->SetBatchSize(batchSize);

  std::cout << "Calculated depth " << depth << std::endl;

  // Generate the cryptocontext
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, securityLevel, sigma, 0, depth, 0, OPTIMIZED, 2, 30, 60);

  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(MULTIPARTY);

  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////


  // Print out the parameters
  std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus()
            << std::endl;
  std::cout
      << "n = "
      << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
      << std::endl;
  std::cout << "log2 q = "
            << log2(cc->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetModulus()
                        .ConvertToDouble())
            << std::endl;

  // Initialize Public Key Containers for # hospital parties


  ////////////////////////////////////////////////////////////
  // Load sketches from csv
  ////////////////////////////////////////////////////////////

  


  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<std::vector<int64_t>> sketch_buckets;
  std::cout << "My code" << std::endl;
  sketch_buckets= FetchSketches(1);
  std::vector<int64_t> vectorOfInts1 = sketch_buckets[0];
  std::vector<int64_t> vectorOfInts2 = sketch_buckets[1];
  std::vector<int64_t> vectorOfInts3 = sketch_buckets[2];


  //initialize public key container for 128 parties 
  LPKeyPair<DCRTPoly> kp1;
  LPKeyPair<DCRTPoly> kp2;
  LPKeyPair<DCRTPoly> kp3;
  LPKeyPair<DCRTPoly> kp4;
  LPKeyPair<DCRTPoly> kp5;
  LPKeyPair<DCRTPoly> kp6;
  LPKeyPair<DCRTPoly> kp7;
  LPKeyPair<DCRTPoly> kp8;
  LPKeyPair<DCRTPoly> kp9;
  LPKeyPair<DCRTPoly> kp10;
  LPKeyPair<DCRTPoly> kp11;
  LPKeyPair<DCRTPoly> kp12;
  LPKeyPair<DCRTPoly> kp13;
  LPKeyPair<DCRTPoly> kp14;
  LPKeyPair<DCRTPoly> kp15;
  LPKeyPair<DCRTPoly> kp16;
  LPKeyPair<DCRTPoly> kp17;
  LPKeyPair<DCRTPoly> kp18;
  LPKeyPair<DCRTPoly> kp19;
  LPKeyPair<DCRTPoly> kp20;
  LPKeyPair<DCRTPoly> kp21;
  LPKeyPair<DCRTPoly> kp22;
  LPKeyPair<DCRTPoly> kp23;
  LPKeyPair<DCRTPoly> kp24;
  LPKeyPair<DCRTPoly> kp25;
  LPKeyPair<DCRTPoly> kp26;
  LPKeyPair<DCRTPoly> kp27;
  LPKeyPair<DCRTPoly> kp28;
  LPKeyPair<DCRTPoly> kp29;
  LPKeyPair<DCRTPoly> kp30;
  LPKeyPair<DCRTPoly> kp31;
  LPKeyPair<DCRTPoly> kp32;
  LPKeyPair<DCRTPoly> kp33;
  LPKeyPair<DCRTPoly> kp34;
  LPKeyPair<DCRTPoly> kp35;
  LPKeyPair<DCRTPoly> kp36;
  LPKeyPair<DCRTPoly> kp37;
  LPKeyPair<DCRTPoly> kp38;
  LPKeyPair<DCRTPoly> kp39;
  LPKeyPair<DCRTPoly> kp40;
  LPKeyPair<DCRTPoly> kp41;
  LPKeyPair<DCRTPoly> kp42;
  LPKeyPair<DCRTPoly> kp43;
  LPKeyPair<DCRTPoly> kp44;
  LPKeyPair<DCRTPoly> kp45;
  LPKeyPair<DCRTPoly> kp46;
  LPKeyPair<DCRTPoly> kp47;
  LPKeyPair<DCRTPoly> kp48;
  LPKeyPair<DCRTPoly> kp49;
  LPKeyPair<DCRTPoly> kp50;
  LPKeyPair<DCRTPoly> kp51;
  LPKeyPair<DCRTPoly> kp52;
  LPKeyPair<DCRTPoly> kp53;
  LPKeyPair<DCRTPoly> kp54;
  LPKeyPair<DCRTPoly> kp55;
  LPKeyPair<DCRTPoly> kp56;
  LPKeyPair<DCRTPoly> kp57;
  LPKeyPair<DCRTPoly> kp58;
  LPKeyPair<DCRTPoly> kp59;
  LPKeyPair<DCRTPoly> kp60;
  LPKeyPair<DCRTPoly> kp61;
  LPKeyPair<DCRTPoly> kp62;
  LPKeyPair<DCRTPoly> kp63;
  LPKeyPair<DCRTPoly> kp64;
  LPKeyPair<DCRTPoly> kp65;
  LPKeyPair<DCRTPoly> kp66;
  LPKeyPair<DCRTPoly> kp67;
  LPKeyPair<DCRTPoly> kp68;
  LPKeyPair<DCRTPoly> kp69;
  LPKeyPair<DCRTPoly> kp70;
  LPKeyPair<DCRTPoly> kp71;
  LPKeyPair<DCRTPoly> kp72;
  LPKeyPair<DCRTPoly> kp73;
  LPKeyPair<DCRTPoly> kp74;
  LPKeyPair<DCRTPoly> kp75;
  LPKeyPair<DCRTPoly> kp76;
  LPKeyPair<DCRTPoly> kp77;
  LPKeyPair<DCRTPoly> kp78;
  LPKeyPair<DCRTPoly> kp79;
  LPKeyPair<DCRTPoly> kp80;
  LPKeyPair<DCRTPoly> kp81;
  LPKeyPair<DCRTPoly> kp82;
  LPKeyPair<DCRTPoly> kp83;
  LPKeyPair<DCRTPoly> kp84;
  LPKeyPair<DCRTPoly> kp85;
  LPKeyPair<DCRTPoly> kp86;
  LPKeyPair<DCRTPoly> kp87;
  LPKeyPair<DCRTPoly> kp88;
  LPKeyPair<DCRTPoly> kp89;
  LPKeyPair<DCRTPoly> kp90;
  LPKeyPair<DCRTPoly> kp91;
  LPKeyPair<DCRTPoly> kp92;
  LPKeyPair<DCRTPoly> kp93;
  LPKeyPair<DCRTPoly> kp94;
  LPKeyPair<DCRTPoly> kp95;
  LPKeyPair<DCRTPoly> kp96;
  LPKeyPair<DCRTPoly> kp97;
  LPKeyPair<DCRTPoly> kp98;
  LPKeyPair<DCRTPoly> kp99;
  LPKeyPair<DCRTPoly> kp100;
  LPKeyPair<DCRTPoly> kp101;
  LPKeyPair<DCRTPoly> kp102;
  LPKeyPair<DCRTPoly> kp103;
  LPKeyPair<DCRTPoly> kp104;
  LPKeyPair<DCRTPoly> kp105;
  LPKeyPair<DCRTPoly> kp106;
  LPKeyPair<DCRTPoly> kp107;
  LPKeyPair<DCRTPoly> kp108;
  LPKeyPair<DCRTPoly> kp109;
  LPKeyPair<DCRTPoly> kp110;
  LPKeyPair<DCRTPoly> kp111;
  LPKeyPair<DCRTPoly> kp112;
  LPKeyPair<DCRTPoly> kp113;
  LPKeyPair<DCRTPoly> kp114;
  LPKeyPair<DCRTPoly> kp115;
  LPKeyPair<DCRTPoly> kp116;
  LPKeyPair<DCRTPoly> kp117;
  LPKeyPair<DCRTPoly> kp118;
  LPKeyPair<DCRTPoly> kp119;
  LPKeyPair<DCRTPoly> kp120;
  LPKeyPair<DCRTPoly> kp121;
  LPKeyPair<DCRTPoly> kp122;
  LPKeyPair<DCRTPoly> kp123;
  LPKeyPair<DCRTPoly> kp124;
  LPKeyPair<DCRTPoly> kp125;
  LPKeyPair<DCRTPoly> kp126;
  LPKeyPair<DCRTPoly> kp127;
  LPKeyPair<DCRTPoly> kp128;
  kp1 = cc->KeyGen();

  // Generate mult key part for lead
  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

  // Generate evalsum key part for lead
  cc->EvalSumKeyGen(kp1.secretKey);
  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
  kp2 = cc->MultipartyKeyGen(kp1.publicKey);
  auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
  auto evalMult_up_to_2 = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
  cc->EvalSumKeyGen(kp2.secretKey); auto evalSumKeys2 = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,kp2.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_2 = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeys2, kp2.publicKey->GetKeyTag());

  //gen keys party 3
  kp3 = cc->MultipartyKeyGen(kp2.publicKey);

  // Generate evalmult key part for party 3
  auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMult_up_to_2);
  auto evalMult_up_to_3 = cc->MultiAddEvalKeys(evalMult_up_to_2, evalMultKey3, kp2.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp3.secretKey);
  auto evalSumKeys3 = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysJoin_to_2, kp3.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_3 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_2, evalSumKeys3, kp3.publicKey->GetKeyTag());

  //gen keys party 4
  kp4 = cc->MultipartyKeyGen(kp3.publicKey);

  // Generate evalmult key part for party 4
  auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMult_up_to_3);
  auto evalMult_up_to_4 = cc->MultiAddEvalKeys(evalMult_up_to_3, evalMultKey4, kp3.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp4.secretKey);
  auto evalSumKeys4 = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeysJoin_to_3, kp4.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_4 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_3, evalSumKeys4, kp4.publicKey->GetKeyTag());

  //gen keys party 5
  kp5 = cc->MultipartyKeyGen(kp4.publicKey);

  // Generate evalmult key part for party 5
  auto evalMultKey5 = cc->MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMult_up_to_4);
  auto evalMult_up_to_5 = cc->MultiAddEvalKeys(evalMult_up_to_4, evalMultKey5, kp4.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp5.secretKey);
  auto evalSumKeys5 = cc->MultiEvalSumKeyGen(kp5.secretKey, evalSumKeysJoin_to_4, kp5.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_5 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_4, evalSumKeys5, kp5.publicKey->GetKeyTag());

  //gen keys party 6
  kp6 = cc->MultipartyKeyGen(kp5.publicKey);

  // Generate evalmult key part for party 6
  auto evalMultKey6 = cc->MultiKeySwitchGen(kp6.secretKey, kp6.secretKey, evalMult_up_to_5);
  auto evalMult_up_to_6 = cc->MultiAddEvalKeys(evalMult_up_to_5, evalMultKey6, kp5.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp6.secretKey);
  auto evalSumKeys6 = cc->MultiEvalSumKeyGen(kp6.secretKey, evalSumKeysJoin_to_5, kp6.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_6 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_5, evalSumKeys6, kp6.publicKey->GetKeyTag());

  //gen keys party 7
  kp7 = cc->MultipartyKeyGen(kp6.publicKey);

  // Generate evalmult key part for party 7
  auto evalMultKey7 = cc->MultiKeySwitchGen(kp7.secretKey, kp7.secretKey, evalMult_up_to_6);
  auto evalMult_up_to_7 = cc->MultiAddEvalKeys(evalMult_up_to_6, evalMultKey7, kp6.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp7.secretKey);
  auto evalSumKeys7 = cc->MultiEvalSumKeyGen(kp7.secretKey, evalSumKeysJoin_to_6, kp7.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_7 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_6, evalSumKeys7, kp7.publicKey->GetKeyTag());

  //gen keys party 8
  kp8 = cc->MultipartyKeyGen(kp7.publicKey);

  // Generate evalmult key part for party 8
  auto evalMultKey8 = cc->MultiKeySwitchGen(kp8.secretKey, kp8.secretKey, evalMult_up_to_7);
  auto evalMult_up_to_8 = cc->MultiAddEvalKeys(evalMult_up_to_7, evalMultKey8, kp7.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp8.secretKey);
  auto evalSumKeys8 = cc->MultiEvalSumKeyGen(kp8.secretKey, evalSumKeysJoin_to_7, kp8.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_8 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_7, evalSumKeys8, kp8.publicKey->GetKeyTag());

  //gen keys party 9
  kp9 = cc->MultipartyKeyGen(kp8.publicKey);

  // Generate evalmult key part for party 9
  auto evalMultKey9 = cc->MultiKeySwitchGen(kp9.secretKey, kp9.secretKey, evalMult_up_to_8);
  auto evalMult_up_to_9 = cc->MultiAddEvalKeys(evalMult_up_to_8, evalMultKey9, kp8.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp9.secretKey);
  auto evalSumKeys9 = cc->MultiEvalSumKeyGen(kp9.secretKey, evalSumKeysJoin_to_8, kp9.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_9 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_8, evalSumKeys9, kp9.publicKey->GetKeyTag());

  //gen keys party 10
  kp10 = cc->MultipartyKeyGen(kp9.publicKey);

  // Generate evalmult key part for party 10
  auto evalMultKey10 = cc->MultiKeySwitchGen(kp10.secretKey, kp10.secretKey, evalMult_up_to_9);
  auto evalMult_up_to_10 = cc->MultiAddEvalKeys(evalMult_up_to_9, evalMultKey10, kp9.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp10.secretKey);
  auto evalSumKeys10 = cc->MultiEvalSumKeyGen(kp10.secretKey, evalSumKeysJoin_to_9, kp10.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_10 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_9, evalSumKeys10, kp10.publicKey->GetKeyTag());

  //gen keys party 11
  kp11 = cc->MultipartyKeyGen(kp10.publicKey);

  // Generate evalmult key part for party 11
  auto evalMultKey11 = cc->MultiKeySwitchGen(kp11.secretKey, kp11.secretKey, evalMult_up_to_10);
  auto evalMult_up_to_11 = cc->MultiAddEvalKeys(evalMult_up_to_10, evalMultKey11, kp10.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp11.secretKey);
  auto evalSumKeys11 = cc->MultiEvalSumKeyGen(kp11.secretKey, evalSumKeysJoin_to_10, kp11.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_11 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_10, evalSumKeys11, kp11.publicKey->GetKeyTag());

  //gen keys party 12
  kp12 = cc->MultipartyKeyGen(kp11.publicKey);

  // Generate evalmult key part for party 12
  auto evalMultKey12 = cc->MultiKeySwitchGen(kp12.secretKey, kp12.secretKey, evalMult_up_to_11);
  auto evalMult_up_to_12 = cc->MultiAddEvalKeys(evalMult_up_to_11, evalMultKey12, kp11.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp12.secretKey);
  auto evalSumKeys12 = cc->MultiEvalSumKeyGen(kp12.secretKey, evalSumKeysJoin_to_11, kp12.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_12 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_11, evalSumKeys12, kp12.publicKey->GetKeyTag());

  //gen keys party 13
  kp13 = cc->MultipartyKeyGen(kp12.publicKey);

  // Generate evalmult key part for party 13
  auto evalMultKey13 = cc->MultiKeySwitchGen(kp13.secretKey, kp13.secretKey, evalMult_up_to_12);
  auto evalMult_up_to_13 = cc->MultiAddEvalKeys(evalMult_up_to_12, evalMultKey13, kp12.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp13.secretKey);
  auto evalSumKeys13 = cc->MultiEvalSumKeyGen(kp13.secretKey, evalSumKeysJoin_to_12, kp13.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_13 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_12, evalSumKeys13, kp13.publicKey->GetKeyTag());

  //gen keys party 14
  kp14 = cc->MultipartyKeyGen(kp13.publicKey);

  // Generate evalmult key part for party 14
  auto evalMultKey14 = cc->MultiKeySwitchGen(kp14.secretKey, kp14.secretKey, evalMult_up_to_13);
  auto evalMult_up_to_14 = cc->MultiAddEvalKeys(evalMult_up_to_13, evalMultKey14, kp13.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp14.secretKey);
  auto evalSumKeys14 = cc->MultiEvalSumKeyGen(kp14.secretKey, evalSumKeysJoin_to_13, kp14.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_14 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_13, evalSumKeys14, kp14.publicKey->GetKeyTag());

  //gen keys party 15
  kp15 = cc->MultipartyKeyGen(kp14.publicKey);

  // Generate evalmult key part for party 15
  auto evalMultKey15 = cc->MultiKeySwitchGen(kp15.secretKey, kp15.secretKey, evalMult_up_to_14);
  auto evalMult_up_to_15 = cc->MultiAddEvalKeys(evalMult_up_to_14, evalMultKey15, kp14.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp15.secretKey);
  auto evalSumKeys15 = cc->MultiEvalSumKeyGen(kp15.secretKey, evalSumKeysJoin_to_14, kp15.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_15 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_14, evalSumKeys15, kp15.publicKey->GetKeyTag());

  //gen keys party 16
  kp16 = cc->MultipartyKeyGen(kp15.publicKey);

  // Generate evalmult key part for party 16
  auto evalMultKey16 = cc->MultiKeySwitchGen(kp16.secretKey, kp16.secretKey, evalMult_up_to_15);
  auto evalMult_up_to_16 = cc->MultiAddEvalKeys(evalMult_up_to_15, evalMultKey16, kp15.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp16.secretKey);
  auto evalSumKeys16 = cc->MultiEvalSumKeyGen(kp16.secretKey, evalSumKeysJoin_to_15, kp16.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_16 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_15, evalSumKeys16, kp16.publicKey->GetKeyTag());

  //gen keys party 17
  kp17 = cc->MultipartyKeyGen(kp16.publicKey);

  // Generate evalmult key part for party 17
  auto evalMultKey17 = cc->MultiKeySwitchGen(kp17.secretKey, kp17.secretKey, evalMult_up_to_16);
  auto evalMult_up_to_17 = cc->MultiAddEvalKeys(evalMult_up_to_16, evalMultKey17, kp16.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp17.secretKey);
  auto evalSumKeys17 = cc->MultiEvalSumKeyGen(kp17.secretKey, evalSumKeysJoin_to_16, kp17.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_17 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_16, evalSumKeys17, kp17.publicKey->GetKeyTag());

  //gen keys party 18
  kp18 = cc->MultipartyKeyGen(kp17.publicKey);

  // Generate evalmult key part for party 18
  auto evalMultKey18 = cc->MultiKeySwitchGen(kp18.secretKey, kp18.secretKey, evalMult_up_to_17);
  auto evalMult_up_to_18 = cc->MultiAddEvalKeys(evalMult_up_to_17, evalMultKey18, kp17.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp18.secretKey);
  auto evalSumKeys18 = cc->MultiEvalSumKeyGen(kp18.secretKey, evalSumKeysJoin_to_17, kp18.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_18 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_17, evalSumKeys18, kp18.publicKey->GetKeyTag());

  //gen keys party 19
  kp19 = cc->MultipartyKeyGen(kp18.publicKey);

  // Generate evalmult key part for party 19
  auto evalMultKey19 = cc->MultiKeySwitchGen(kp19.secretKey, kp19.secretKey, evalMult_up_to_18);
  auto evalMult_up_to_19 = cc->MultiAddEvalKeys(evalMult_up_to_18, evalMultKey19, kp18.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp19.secretKey);
  auto evalSumKeys19 = cc->MultiEvalSumKeyGen(kp19.secretKey, evalSumKeysJoin_to_18, kp19.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_19 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_18, evalSumKeys19, kp19.publicKey->GetKeyTag());

  //gen keys party 20
  kp20 = cc->MultipartyKeyGen(kp19.publicKey);

  // Generate evalmult key part for party 20
  auto evalMultKey20 = cc->MultiKeySwitchGen(kp20.secretKey, kp20.secretKey, evalMult_up_to_19);
  auto evalMult_up_to_20 = cc->MultiAddEvalKeys(evalMult_up_to_19, evalMultKey20, kp19.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp20.secretKey);
  auto evalSumKeys20 = cc->MultiEvalSumKeyGen(kp20.secretKey, evalSumKeysJoin_to_19, kp20.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_20 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_19, evalSumKeys20, kp20.publicKey->GetKeyTag());

  //gen keys party 21
  kp21 = cc->MultipartyKeyGen(kp20.publicKey);

  // Generate evalmult key part for party 21
  auto evalMultKey21 = cc->MultiKeySwitchGen(kp21.secretKey, kp21.secretKey, evalMult_up_to_20);
  auto evalMult_up_to_21 = cc->MultiAddEvalKeys(evalMult_up_to_20, evalMultKey21, kp20.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp21.secretKey);
  auto evalSumKeys21 = cc->MultiEvalSumKeyGen(kp21.secretKey, evalSumKeysJoin_to_20, kp21.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_21 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_20, evalSumKeys21, kp21.publicKey->GetKeyTag());

  //gen keys party 22
  kp22 = cc->MultipartyKeyGen(kp21.publicKey);

  // Generate evalmult key part for party 22
  auto evalMultKey22 = cc->MultiKeySwitchGen(kp22.secretKey, kp22.secretKey, evalMult_up_to_21);
  auto evalMult_up_to_22 = cc->MultiAddEvalKeys(evalMult_up_to_21, evalMultKey22, kp21.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp22.secretKey);
  auto evalSumKeys22 = cc->MultiEvalSumKeyGen(kp22.secretKey, evalSumKeysJoin_to_21, kp22.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_22 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_21, evalSumKeys22, kp22.publicKey->GetKeyTag());

  //gen keys party 23
  kp23 = cc->MultipartyKeyGen(kp22.publicKey);

  // Generate evalmult key part for party 23
  auto evalMultKey23 = cc->MultiKeySwitchGen(kp23.secretKey, kp23.secretKey, evalMult_up_to_22);
  auto evalMult_up_to_23 = cc->MultiAddEvalKeys(evalMult_up_to_22, evalMultKey23, kp22.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp23.secretKey);
  auto evalSumKeys23 = cc->MultiEvalSumKeyGen(kp23.secretKey, evalSumKeysJoin_to_22, kp23.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_23 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_22, evalSumKeys23, kp23.publicKey->GetKeyTag());

  //gen keys party 24
  kp24 = cc->MultipartyKeyGen(kp23.publicKey);

  // Generate evalmult key part for party 24
  auto evalMultKey24 = cc->MultiKeySwitchGen(kp24.secretKey, kp24.secretKey, evalMult_up_to_23);
  auto evalMult_up_to_24 = cc->MultiAddEvalKeys(evalMult_up_to_23, evalMultKey24, kp23.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp24.secretKey);
  auto evalSumKeys24 = cc->MultiEvalSumKeyGen(kp24.secretKey, evalSumKeysJoin_to_23, kp24.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_24 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_23, evalSumKeys24, kp24.publicKey->GetKeyTag());

  //gen keys party 25
  kp25 = cc->MultipartyKeyGen(kp24.publicKey);

  // Generate evalmult key part for party 25
  auto evalMultKey25 = cc->MultiKeySwitchGen(kp25.secretKey, kp25.secretKey, evalMult_up_to_24);
  auto evalMult_up_to_25 = cc->MultiAddEvalKeys(evalMult_up_to_24, evalMultKey25, kp24.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp25.secretKey);
  auto evalSumKeys25 = cc->MultiEvalSumKeyGen(kp25.secretKey, evalSumKeysJoin_to_24, kp25.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_25 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_24, evalSumKeys25, kp25.publicKey->GetKeyTag());

  //gen keys party 26
  kp26 = cc->MultipartyKeyGen(kp25.publicKey);

  // Generate evalmult key part for party 26
  auto evalMultKey26 = cc->MultiKeySwitchGen(kp26.secretKey, kp26.secretKey, evalMult_up_to_25);
  auto evalMult_up_to_26 = cc->MultiAddEvalKeys(evalMult_up_to_25, evalMultKey26, kp25.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp26.secretKey);
  auto evalSumKeys26 = cc->MultiEvalSumKeyGen(kp26.secretKey, evalSumKeysJoin_to_25, kp26.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_26 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_25, evalSumKeys26, kp26.publicKey->GetKeyTag());

  //gen keys party 27
  kp27 = cc->MultipartyKeyGen(kp26.publicKey);

  // Generate evalmult key part for party 27
  auto evalMultKey27 = cc->MultiKeySwitchGen(kp27.secretKey, kp27.secretKey, evalMult_up_to_26);
  auto evalMult_up_to_27 = cc->MultiAddEvalKeys(evalMult_up_to_26, evalMultKey27, kp26.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp27.secretKey);
  auto evalSumKeys27 = cc->MultiEvalSumKeyGen(kp27.secretKey, evalSumKeysJoin_to_26, kp27.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_27 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_26, evalSumKeys27, kp27.publicKey->GetKeyTag());

  //gen keys party 28
  kp28 = cc->MultipartyKeyGen(kp27.publicKey);

  // Generate evalmult key part for party 28
  auto evalMultKey28 = cc->MultiKeySwitchGen(kp28.secretKey, kp28.secretKey, evalMult_up_to_27);
  auto evalMult_up_to_28 = cc->MultiAddEvalKeys(evalMult_up_to_27, evalMultKey28, kp27.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp28.secretKey);
  auto evalSumKeys28 = cc->MultiEvalSumKeyGen(kp28.secretKey, evalSumKeysJoin_to_27, kp28.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_28 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_27, evalSumKeys28, kp28.publicKey->GetKeyTag());

  //gen keys party 29
  kp29 = cc->MultipartyKeyGen(kp28.publicKey);

  // Generate evalmult key part for party 29
  auto evalMultKey29 = cc->MultiKeySwitchGen(kp29.secretKey, kp29.secretKey, evalMult_up_to_28);
  auto evalMult_up_to_29 = cc->MultiAddEvalKeys(evalMult_up_to_28, evalMultKey29, kp28.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp29.secretKey);
  auto evalSumKeys29 = cc->MultiEvalSumKeyGen(kp29.secretKey, evalSumKeysJoin_to_28, kp29.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_29 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_28, evalSumKeys29, kp29.publicKey->GetKeyTag());

  //gen keys party 30
  kp30 = cc->MultipartyKeyGen(kp29.publicKey);

  // Generate evalmult key part for party 30
  auto evalMultKey30 = cc->MultiKeySwitchGen(kp30.secretKey, kp30.secretKey, evalMult_up_to_29);
  auto evalMult_up_to_30 = cc->MultiAddEvalKeys(evalMult_up_to_29, evalMultKey30, kp29.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp30.secretKey);
  auto evalSumKeys30 = cc->MultiEvalSumKeyGen(kp30.secretKey, evalSumKeysJoin_to_29, kp30.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_30 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_29, evalSumKeys30, kp30.publicKey->GetKeyTag());

  //gen keys party 31
  kp31 = cc->MultipartyKeyGen(kp30.publicKey);

  // Generate evalmult key part for party 31
  auto evalMultKey31 = cc->MultiKeySwitchGen(kp31.secretKey, kp31.secretKey, evalMult_up_to_30);
  auto evalMult_up_to_31 = cc->MultiAddEvalKeys(evalMult_up_to_30, evalMultKey31, kp30.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp31.secretKey);
  auto evalSumKeys31 = cc->MultiEvalSumKeyGen(kp31.secretKey, evalSumKeysJoin_to_30, kp31.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_31 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_30, evalSumKeys31, kp31.publicKey->GetKeyTag());

  //gen keys party 32
  kp32 = cc->MultipartyKeyGen(kp31.publicKey);

  // Generate evalmult key part for party 32
  auto evalMultKey32 = cc->MultiKeySwitchGen(kp32.secretKey, kp32.secretKey, evalMult_up_to_31);
  auto evalMult_up_to_32 = cc->MultiAddEvalKeys(evalMult_up_to_31, evalMultKey32, kp31.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp32.secretKey);
  auto evalSumKeys32 = cc->MultiEvalSumKeyGen(kp32.secretKey, evalSumKeysJoin_to_31, kp32.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_32 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_31, evalSumKeys32, kp32.publicKey->GetKeyTag());

  //gen keys party 33
  kp33 = cc->MultipartyKeyGen(kp32.publicKey);

  // Generate evalmult key part for party 33
  auto evalMultKey33 = cc->MultiKeySwitchGen(kp33.secretKey, kp33.secretKey, evalMult_up_to_32);
  auto evalMult_up_to_33 = cc->MultiAddEvalKeys(evalMult_up_to_32, evalMultKey33, kp32.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp33.secretKey);
  auto evalSumKeys33 = cc->MultiEvalSumKeyGen(kp33.secretKey, evalSumKeysJoin_to_32, kp33.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_33 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_32, evalSumKeys33, kp33.publicKey->GetKeyTag());

  //gen keys party 34
  kp34 = cc->MultipartyKeyGen(kp33.publicKey);

  // Generate evalmult key part for party 34
  auto evalMultKey34 = cc->MultiKeySwitchGen(kp34.secretKey, kp34.secretKey, evalMult_up_to_33);
  auto evalMult_up_to_34 = cc->MultiAddEvalKeys(evalMult_up_to_33, evalMultKey34, kp33.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp34.secretKey);
  auto evalSumKeys34 = cc->MultiEvalSumKeyGen(kp34.secretKey, evalSumKeysJoin_to_33, kp34.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_34 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_33, evalSumKeys34, kp34.publicKey->GetKeyTag());

  //gen keys party 35
  kp35 = cc->MultipartyKeyGen(kp34.publicKey);

  // Generate evalmult key part for party 35
  auto evalMultKey35 = cc->MultiKeySwitchGen(kp35.secretKey, kp35.secretKey, evalMult_up_to_34);
  auto evalMult_up_to_35 = cc->MultiAddEvalKeys(evalMult_up_to_34, evalMultKey35, kp34.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp35.secretKey);
  auto evalSumKeys35 = cc->MultiEvalSumKeyGen(kp35.secretKey, evalSumKeysJoin_to_34, kp35.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_35 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_34, evalSumKeys35, kp35.publicKey->GetKeyTag());

  //gen keys party 36
  kp36 = cc->MultipartyKeyGen(kp35.publicKey);

  // Generate evalmult key part for party 36
  auto evalMultKey36 = cc->MultiKeySwitchGen(kp36.secretKey, kp36.secretKey, evalMult_up_to_35);
  auto evalMult_up_to_36 = cc->MultiAddEvalKeys(evalMult_up_to_35, evalMultKey36, kp35.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp36.secretKey);
  auto evalSumKeys36 = cc->MultiEvalSumKeyGen(kp36.secretKey, evalSumKeysJoin_to_35, kp36.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_36 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_35, evalSumKeys36, kp36.publicKey->GetKeyTag());

  //gen keys party 37
  kp37 = cc->MultipartyKeyGen(kp36.publicKey);

  // Generate evalmult key part for party 37
  auto evalMultKey37 = cc->MultiKeySwitchGen(kp37.secretKey, kp37.secretKey, evalMult_up_to_36);
  auto evalMult_up_to_37 = cc->MultiAddEvalKeys(evalMult_up_to_36, evalMultKey37, kp36.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp37.secretKey);
  auto evalSumKeys37 = cc->MultiEvalSumKeyGen(kp37.secretKey, evalSumKeysJoin_to_36, kp37.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_37 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_36, evalSumKeys37, kp37.publicKey->GetKeyTag());

  //gen keys party 38
  kp38 = cc->MultipartyKeyGen(kp37.publicKey);

  // Generate evalmult key part for party 38
  auto evalMultKey38 = cc->MultiKeySwitchGen(kp38.secretKey, kp38.secretKey, evalMult_up_to_37);
  auto evalMult_up_to_38 = cc->MultiAddEvalKeys(evalMult_up_to_37, evalMultKey38, kp37.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp38.secretKey);
  auto evalSumKeys38 = cc->MultiEvalSumKeyGen(kp38.secretKey, evalSumKeysJoin_to_37, kp38.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_38 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_37, evalSumKeys38, kp38.publicKey->GetKeyTag());

  //gen keys party 39
  kp39 = cc->MultipartyKeyGen(kp38.publicKey);

  // Generate evalmult key part for party 39
  auto evalMultKey39 = cc->MultiKeySwitchGen(kp39.secretKey, kp39.secretKey, evalMult_up_to_38);
  auto evalMult_up_to_39 = cc->MultiAddEvalKeys(evalMult_up_to_38, evalMultKey39, kp38.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp39.secretKey);
  auto evalSumKeys39 = cc->MultiEvalSumKeyGen(kp39.secretKey, evalSumKeysJoin_to_38, kp39.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_39 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_38, evalSumKeys39, kp39.publicKey->GetKeyTag());

  //gen keys party 40
  kp40 = cc->MultipartyKeyGen(kp39.publicKey);

  // Generate evalmult key part for party 40
  auto evalMultKey40 = cc->MultiKeySwitchGen(kp40.secretKey, kp40.secretKey, evalMult_up_to_39);
  auto evalMult_up_to_40 = cc->MultiAddEvalKeys(evalMult_up_to_39, evalMultKey40, kp39.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp40.secretKey);
  auto evalSumKeys40 = cc->MultiEvalSumKeyGen(kp40.secretKey, evalSumKeysJoin_to_39, kp40.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_40 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_39, evalSumKeys40, kp40.publicKey->GetKeyTag());

  //gen keys party 41
  kp41 = cc->MultipartyKeyGen(kp40.publicKey);

  // Generate evalmult key part for party 41
  auto evalMultKey41 = cc->MultiKeySwitchGen(kp41.secretKey, kp41.secretKey, evalMult_up_to_40);
  auto evalMult_up_to_41 = cc->MultiAddEvalKeys(evalMult_up_to_40, evalMultKey41, kp40.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp41.secretKey);
  auto evalSumKeys41 = cc->MultiEvalSumKeyGen(kp41.secretKey, evalSumKeysJoin_to_40, kp41.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_41 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_40, evalSumKeys41, kp41.publicKey->GetKeyTag());

  //gen keys party 42
  kp42 = cc->MultipartyKeyGen(kp41.publicKey);

  // Generate evalmult key part for party 42
  auto evalMultKey42 = cc->MultiKeySwitchGen(kp42.secretKey, kp42.secretKey, evalMult_up_to_41);
  auto evalMult_up_to_42 = cc->MultiAddEvalKeys(evalMult_up_to_41, evalMultKey42, kp41.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp42.secretKey);
  auto evalSumKeys42 = cc->MultiEvalSumKeyGen(kp42.secretKey, evalSumKeysJoin_to_41, kp42.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_42 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_41, evalSumKeys42, kp42.publicKey->GetKeyTag());

  //gen keys party 43
  kp43 = cc->MultipartyKeyGen(kp42.publicKey);

  // Generate evalmult key part for party 43
  auto evalMultKey43 = cc->MultiKeySwitchGen(kp43.secretKey, kp43.secretKey, evalMult_up_to_42);
  auto evalMult_up_to_43 = cc->MultiAddEvalKeys(evalMult_up_to_42, evalMultKey43, kp42.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp43.secretKey);
  auto evalSumKeys43 = cc->MultiEvalSumKeyGen(kp43.secretKey, evalSumKeysJoin_to_42, kp43.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_43 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_42, evalSumKeys43, kp43.publicKey->GetKeyTag());

  //gen keys party 44
  kp44 = cc->MultipartyKeyGen(kp43.publicKey);

  // Generate evalmult key part for party 44
  auto evalMultKey44 = cc->MultiKeySwitchGen(kp44.secretKey, kp44.secretKey, evalMult_up_to_43);
  auto evalMult_up_to_44 = cc->MultiAddEvalKeys(evalMult_up_to_43, evalMultKey44, kp43.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp44.secretKey);
  auto evalSumKeys44 = cc->MultiEvalSumKeyGen(kp44.secretKey, evalSumKeysJoin_to_43, kp44.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_44 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_43, evalSumKeys44, kp44.publicKey->GetKeyTag());

  //gen keys party 45
  kp45 = cc->MultipartyKeyGen(kp44.publicKey);

  // Generate evalmult key part for party 45
  auto evalMultKey45 = cc->MultiKeySwitchGen(kp45.secretKey, kp45.secretKey, evalMult_up_to_44);
  auto evalMult_up_to_45 = cc->MultiAddEvalKeys(evalMult_up_to_44, evalMultKey45, kp44.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp45.secretKey);
  auto evalSumKeys45 = cc->MultiEvalSumKeyGen(kp45.secretKey, evalSumKeysJoin_to_44, kp45.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_45 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_44, evalSumKeys45, kp45.publicKey->GetKeyTag());

  //gen keys party 46
  kp46 = cc->MultipartyKeyGen(kp45.publicKey);

  // Generate evalmult key part for party 46
  auto evalMultKey46 = cc->MultiKeySwitchGen(kp46.secretKey, kp46.secretKey, evalMult_up_to_45);
  auto evalMult_up_to_46 = cc->MultiAddEvalKeys(evalMult_up_to_45, evalMultKey46, kp45.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp46.secretKey);
  auto evalSumKeys46 = cc->MultiEvalSumKeyGen(kp46.secretKey, evalSumKeysJoin_to_45, kp46.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_46 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_45, evalSumKeys46, kp46.publicKey->GetKeyTag());

  //gen keys party 47
  kp47 = cc->MultipartyKeyGen(kp46.publicKey);

  // Generate evalmult key part for party 47
  auto evalMultKey47 = cc->MultiKeySwitchGen(kp47.secretKey, kp47.secretKey, evalMult_up_to_46);
  auto evalMult_up_to_47 = cc->MultiAddEvalKeys(evalMult_up_to_46, evalMultKey47, kp46.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp47.secretKey);
  auto evalSumKeys47 = cc->MultiEvalSumKeyGen(kp47.secretKey, evalSumKeysJoin_to_46, kp47.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_47 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_46, evalSumKeys47, kp47.publicKey->GetKeyTag());

  //gen keys party 48
  kp48 = cc->MultipartyKeyGen(kp47.publicKey);

  // Generate evalmult key part for party 48
  auto evalMultKey48 = cc->MultiKeySwitchGen(kp48.secretKey, kp48.secretKey, evalMult_up_to_47);
  auto evalMult_up_to_48 = cc->MultiAddEvalKeys(evalMult_up_to_47, evalMultKey48, kp47.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp48.secretKey);
  auto evalSumKeys48 = cc->MultiEvalSumKeyGen(kp48.secretKey, evalSumKeysJoin_to_47, kp48.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_48 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_47, evalSumKeys48, kp48.publicKey->GetKeyTag());

  //gen keys party 49
  kp49 = cc->MultipartyKeyGen(kp48.publicKey);

  // Generate evalmult key part for party 49
  auto evalMultKey49 = cc->MultiKeySwitchGen(kp49.secretKey, kp49.secretKey, evalMult_up_to_48);
  auto evalMult_up_to_49 = cc->MultiAddEvalKeys(evalMult_up_to_48, evalMultKey49, kp48.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp49.secretKey);
  auto evalSumKeys49 = cc->MultiEvalSumKeyGen(kp49.secretKey, evalSumKeysJoin_to_48, kp49.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_49 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_48, evalSumKeys49, kp49.publicKey->GetKeyTag());

  //gen keys party 50
  kp50 = cc->MultipartyKeyGen(kp49.publicKey);

  // Generate evalmult key part for party 50
  auto evalMultKey50 = cc->MultiKeySwitchGen(kp50.secretKey, kp50.secretKey, evalMult_up_to_49);
  auto evalMult_up_to_50 = cc->MultiAddEvalKeys(evalMult_up_to_49, evalMultKey50, kp49.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp50.secretKey);
  auto evalSumKeys50 = cc->MultiEvalSumKeyGen(kp50.secretKey, evalSumKeysJoin_to_49, kp50.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_50 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_49, evalSumKeys50, kp50.publicKey->GetKeyTag());

  //gen keys party 51
  kp51 = cc->MultipartyKeyGen(kp50.publicKey);

  // Generate evalmult key part for party 51
  auto evalMultKey51 = cc->MultiKeySwitchGen(kp51.secretKey, kp51.secretKey, evalMult_up_to_50);
  auto evalMult_up_to_51 = cc->MultiAddEvalKeys(evalMult_up_to_50, evalMultKey51, kp50.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp51.secretKey);
  auto evalSumKeys51 = cc->MultiEvalSumKeyGen(kp51.secretKey, evalSumKeysJoin_to_50, kp51.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_51 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_50, evalSumKeys51, kp51.publicKey->GetKeyTag());

  //gen keys party 52
  kp52 = cc->MultipartyKeyGen(kp51.publicKey);

  // Generate evalmult key part for party 52
  auto evalMultKey52 = cc->MultiKeySwitchGen(kp52.secretKey, kp52.secretKey, evalMult_up_to_51);
  auto evalMult_up_to_52 = cc->MultiAddEvalKeys(evalMult_up_to_51, evalMultKey52, kp51.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp52.secretKey);
  auto evalSumKeys52 = cc->MultiEvalSumKeyGen(kp52.secretKey, evalSumKeysJoin_to_51, kp52.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_52 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_51, evalSumKeys52, kp52.publicKey->GetKeyTag());

  //gen keys party 53
  kp53 = cc->MultipartyKeyGen(kp52.publicKey);

  // Generate evalmult key part for party 53
  auto evalMultKey53 = cc->MultiKeySwitchGen(kp53.secretKey, kp53.secretKey, evalMult_up_to_52);
  auto evalMult_up_to_53 = cc->MultiAddEvalKeys(evalMult_up_to_52, evalMultKey53, kp52.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp53.secretKey);
  auto evalSumKeys53 = cc->MultiEvalSumKeyGen(kp53.secretKey, evalSumKeysJoin_to_52, kp53.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_53 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_52, evalSumKeys53, kp53.publicKey->GetKeyTag());

  //gen keys party 54
  kp54 = cc->MultipartyKeyGen(kp53.publicKey);

  // Generate evalmult key part for party 54
  auto evalMultKey54 = cc->MultiKeySwitchGen(kp54.secretKey, kp54.secretKey, evalMult_up_to_53);
  auto evalMult_up_to_54 = cc->MultiAddEvalKeys(evalMult_up_to_53, evalMultKey54, kp53.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp54.secretKey);
  auto evalSumKeys54 = cc->MultiEvalSumKeyGen(kp54.secretKey, evalSumKeysJoin_to_53, kp54.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_54 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_53, evalSumKeys54, kp54.publicKey->GetKeyTag());

  //gen keys party 55
  kp55 = cc->MultipartyKeyGen(kp54.publicKey);

  // Generate evalmult key part for party 55
  auto evalMultKey55 = cc->MultiKeySwitchGen(kp55.secretKey, kp55.secretKey, evalMult_up_to_54);
  auto evalMult_up_to_55 = cc->MultiAddEvalKeys(evalMult_up_to_54, evalMultKey55, kp54.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp55.secretKey);
  auto evalSumKeys55 = cc->MultiEvalSumKeyGen(kp55.secretKey, evalSumKeysJoin_to_54, kp55.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_55 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_54, evalSumKeys55, kp55.publicKey->GetKeyTag());

  //gen keys party 56
  kp56 = cc->MultipartyKeyGen(kp55.publicKey);

  // Generate evalmult key part for party 56
  auto evalMultKey56 = cc->MultiKeySwitchGen(kp56.secretKey, kp56.secretKey, evalMult_up_to_55);
  auto evalMult_up_to_56 = cc->MultiAddEvalKeys(evalMult_up_to_55, evalMultKey56, kp55.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp56.secretKey);
  auto evalSumKeys56 = cc->MultiEvalSumKeyGen(kp56.secretKey, evalSumKeysJoin_to_55, kp56.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_56 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_55, evalSumKeys56, kp56.publicKey->GetKeyTag());

  //gen keys party 57
  kp57 = cc->MultipartyKeyGen(kp56.publicKey);

  // Generate evalmult key part for party 57
  auto evalMultKey57 = cc->MultiKeySwitchGen(kp57.secretKey, kp57.secretKey, evalMult_up_to_56);
  auto evalMult_up_to_57 = cc->MultiAddEvalKeys(evalMult_up_to_56, evalMultKey57, kp56.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp57.secretKey);
  auto evalSumKeys57 = cc->MultiEvalSumKeyGen(kp57.secretKey, evalSumKeysJoin_to_56, kp57.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_57 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_56, evalSumKeys57, kp57.publicKey->GetKeyTag());

  //gen keys party 58
  kp58 = cc->MultipartyKeyGen(kp57.publicKey);

  // Generate evalmult key part for party 58
  auto evalMultKey58 = cc->MultiKeySwitchGen(kp58.secretKey, kp58.secretKey, evalMult_up_to_57);
  auto evalMult_up_to_58 = cc->MultiAddEvalKeys(evalMult_up_to_57, evalMultKey58, kp57.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp58.secretKey);
  auto evalSumKeys58 = cc->MultiEvalSumKeyGen(kp58.secretKey, evalSumKeysJoin_to_57, kp58.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_58 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_57, evalSumKeys58, kp58.publicKey->GetKeyTag());

  //gen keys party 59
  kp59 = cc->MultipartyKeyGen(kp58.publicKey);

  // Generate evalmult key part for party 59
  auto evalMultKey59 = cc->MultiKeySwitchGen(kp59.secretKey, kp59.secretKey, evalMult_up_to_58);
  auto evalMult_up_to_59 = cc->MultiAddEvalKeys(evalMult_up_to_58, evalMultKey59, kp58.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp59.secretKey);
  auto evalSumKeys59 = cc->MultiEvalSumKeyGen(kp59.secretKey, evalSumKeysJoin_to_58, kp59.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_59 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_58, evalSumKeys59, kp59.publicKey->GetKeyTag());

  //gen keys party 60
  kp60 = cc->MultipartyKeyGen(kp59.publicKey);

  // Generate evalmult key part for party 60
  auto evalMultKey60 = cc->MultiKeySwitchGen(kp60.secretKey, kp60.secretKey, evalMult_up_to_59);
  auto evalMult_up_to_60 = cc->MultiAddEvalKeys(evalMult_up_to_59, evalMultKey60, kp59.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp60.secretKey);
  auto evalSumKeys60 = cc->MultiEvalSumKeyGen(kp60.secretKey, evalSumKeysJoin_to_59, kp60.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_60 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_59, evalSumKeys60, kp60.publicKey->GetKeyTag());

  //gen keys party 61
  kp61 = cc->MultipartyKeyGen(kp60.publicKey);

  // Generate evalmult key part for party 61
  auto evalMultKey61 = cc->MultiKeySwitchGen(kp61.secretKey, kp61.secretKey, evalMult_up_to_60);
  auto evalMult_up_to_61 = cc->MultiAddEvalKeys(evalMult_up_to_60, evalMultKey61, kp60.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp61.secretKey);
  auto evalSumKeys61 = cc->MultiEvalSumKeyGen(kp61.secretKey, evalSumKeysJoin_to_60, kp61.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_61 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_60, evalSumKeys61, kp61.publicKey->GetKeyTag());

  //gen keys party 62
  kp62 = cc->MultipartyKeyGen(kp61.publicKey);

  // Generate evalmult key part for party 62
  auto evalMultKey62 = cc->MultiKeySwitchGen(kp62.secretKey, kp62.secretKey, evalMult_up_to_61);
  auto evalMult_up_to_62 = cc->MultiAddEvalKeys(evalMult_up_to_61, evalMultKey62, kp61.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp62.secretKey);
  auto evalSumKeys62 = cc->MultiEvalSumKeyGen(kp62.secretKey, evalSumKeysJoin_to_61, kp62.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_62 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_61, evalSumKeys62, kp62.publicKey->GetKeyTag());

  //gen keys party 63
  kp63 = cc->MultipartyKeyGen(kp62.publicKey);

  // Generate evalmult key part for party 63
  auto evalMultKey63 = cc->MultiKeySwitchGen(kp63.secretKey, kp63.secretKey, evalMult_up_to_62);
  auto evalMult_up_to_63 = cc->MultiAddEvalKeys(evalMult_up_to_62, evalMultKey63, kp62.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp63.secretKey);
  auto evalSumKeys63 = cc->MultiEvalSumKeyGen(kp63.secretKey, evalSumKeysJoin_to_62, kp63.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_63 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_62, evalSumKeys63, kp63.publicKey->GetKeyTag());

  //gen keys party 64
  kp64 = cc->MultipartyKeyGen(kp63.publicKey);

  // Generate evalmult key part for party 64
  auto evalMultKey64 = cc->MultiKeySwitchGen(kp64.secretKey, kp64.secretKey, evalMult_up_to_63);
  auto evalMult_up_to_64 = cc->MultiAddEvalKeys(evalMult_up_to_63, evalMultKey64, kp63.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp64.secretKey);
  auto evalSumKeys64 = cc->MultiEvalSumKeyGen(kp64.secretKey, evalSumKeysJoin_to_63, kp64.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_64 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_63, evalSumKeys64, kp64.publicKey->GetKeyTag());

  //gen keys party 65
  kp65 = cc->MultipartyKeyGen(kp64.publicKey);

  // Generate evalmult key part for party 65
  auto evalMultKey65 = cc->MultiKeySwitchGen(kp65.secretKey, kp65.secretKey, evalMult_up_to_64);
  auto evalMult_up_to_65 = cc->MultiAddEvalKeys(evalMult_up_to_64, evalMultKey65, kp64.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp65.secretKey);
  auto evalSumKeys65 = cc->MultiEvalSumKeyGen(kp65.secretKey, evalSumKeysJoin_to_64, kp65.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_65 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_64, evalSumKeys65, kp65.publicKey->GetKeyTag());

  //gen keys party 66
  kp66 = cc->MultipartyKeyGen(kp65.publicKey);

  // Generate evalmult key part for party 66
  auto evalMultKey66 = cc->MultiKeySwitchGen(kp66.secretKey, kp66.secretKey, evalMult_up_to_65);
  auto evalMult_up_to_66 = cc->MultiAddEvalKeys(evalMult_up_to_65, evalMultKey66, kp65.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp66.secretKey);
  auto evalSumKeys66 = cc->MultiEvalSumKeyGen(kp66.secretKey, evalSumKeysJoin_to_65, kp66.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_66 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_65, evalSumKeys66, kp66.publicKey->GetKeyTag());

  //gen keys party 67
  kp67 = cc->MultipartyKeyGen(kp66.publicKey);

  // Generate evalmult key part for party 67
  auto evalMultKey67 = cc->MultiKeySwitchGen(kp67.secretKey, kp67.secretKey, evalMult_up_to_66);
  auto evalMult_up_to_67 = cc->MultiAddEvalKeys(evalMult_up_to_66, evalMultKey67, kp66.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp67.secretKey);
  auto evalSumKeys67 = cc->MultiEvalSumKeyGen(kp67.secretKey, evalSumKeysJoin_to_66, kp67.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_67 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_66, evalSumKeys67, kp67.publicKey->GetKeyTag());

  //gen keys party 68
  kp68 = cc->MultipartyKeyGen(kp67.publicKey);

  // Generate evalmult key part for party 68
  auto evalMultKey68 = cc->MultiKeySwitchGen(kp68.secretKey, kp68.secretKey, evalMult_up_to_67);
  auto evalMult_up_to_68 = cc->MultiAddEvalKeys(evalMult_up_to_67, evalMultKey68, kp67.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp68.secretKey);
  auto evalSumKeys68 = cc->MultiEvalSumKeyGen(kp68.secretKey, evalSumKeysJoin_to_67, kp68.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_68 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_67, evalSumKeys68, kp68.publicKey->GetKeyTag());

  //gen keys party 69
  kp69 = cc->MultipartyKeyGen(kp68.publicKey);

  // Generate evalmult key part for party 69
  auto evalMultKey69 = cc->MultiKeySwitchGen(kp69.secretKey, kp69.secretKey, evalMult_up_to_68);
  auto evalMult_up_to_69 = cc->MultiAddEvalKeys(evalMult_up_to_68, evalMultKey69, kp68.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp69.secretKey);
  auto evalSumKeys69 = cc->MultiEvalSumKeyGen(kp69.secretKey, evalSumKeysJoin_to_68, kp69.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_69 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_68, evalSumKeys69, kp69.publicKey->GetKeyTag());

  //gen keys party 70
  kp70 = cc->MultipartyKeyGen(kp69.publicKey);

  // Generate evalmult key part for party 70
  auto evalMultKey70 = cc->MultiKeySwitchGen(kp70.secretKey, kp70.secretKey, evalMult_up_to_69);
  auto evalMult_up_to_70 = cc->MultiAddEvalKeys(evalMult_up_to_69, evalMultKey70, kp69.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp70.secretKey);
  auto evalSumKeys70 = cc->MultiEvalSumKeyGen(kp70.secretKey, evalSumKeysJoin_to_69, kp70.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_70 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_69, evalSumKeys70, kp70.publicKey->GetKeyTag());

  //gen keys party 71
  kp71 = cc->MultipartyKeyGen(kp70.publicKey);

  // Generate evalmult key part for party 71
  auto evalMultKey71 = cc->MultiKeySwitchGen(kp71.secretKey, kp71.secretKey, evalMult_up_to_70);
  auto evalMult_up_to_71 = cc->MultiAddEvalKeys(evalMult_up_to_70, evalMultKey71, kp70.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp71.secretKey);
  auto evalSumKeys71 = cc->MultiEvalSumKeyGen(kp71.secretKey, evalSumKeysJoin_to_70, kp71.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_71 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_70, evalSumKeys71, kp71.publicKey->GetKeyTag());

  //gen keys party 72
  kp72 = cc->MultipartyKeyGen(kp71.publicKey);

  // Generate evalmult key part for party 72
  auto evalMultKey72 = cc->MultiKeySwitchGen(kp72.secretKey, kp72.secretKey, evalMult_up_to_71);
  auto evalMult_up_to_72 = cc->MultiAddEvalKeys(evalMult_up_to_71, evalMultKey72, kp71.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp72.secretKey);
  auto evalSumKeys72 = cc->MultiEvalSumKeyGen(kp72.secretKey, evalSumKeysJoin_to_71, kp72.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_72 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_71, evalSumKeys72, kp72.publicKey->GetKeyTag());

  //gen keys party 73
  kp73 = cc->MultipartyKeyGen(kp72.publicKey);

  // Generate evalmult key part for party 73
  auto evalMultKey73 = cc->MultiKeySwitchGen(kp73.secretKey, kp73.secretKey, evalMult_up_to_72);
  auto evalMult_up_to_73 = cc->MultiAddEvalKeys(evalMult_up_to_72, evalMultKey73, kp72.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp73.secretKey);
  auto evalSumKeys73 = cc->MultiEvalSumKeyGen(kp73.secretKey, evalSumKeysJoin_to_72, kp73.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_73 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_72, evalSumKeys73, kp73.publicKey->GetKeyTag());

  //gen keys party 74
  kp74 = cc->MultipartyKeyGen(kp73.publicKey);

  // Generate evalmult key part for party 74
  auto evalMultKey74 = cc->MultiKeySwitchGen(kp74.secretKey, kp74.secretKey, evalMult_up_to_73);
  auto evalMult_up_to_74 = cc->MultiAddEvalKeys(evalMult_up_to_73, evalMultKey74, kp73.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp74.secretKey);
  auto evalSumKeys74 = cc->MultiEvalSumKeyGen(kp74.secretKey, evalSumKeysJoin_to_73, kp74.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_74 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_73, evalSumKeys74, kp74.publicKey->GetKeyTag());

  //gen keys party 75
  kp75 = cc->MultipartyKeyGen(kp74.publicKey);

  // Generate evalmult key part for party 75
  auto evalMultKey75 = cc->MultiKeySwitchGen(kp75.secretKey, kp75.secretKey, evalMult_up_to_74);
  auto evalMult_up_to_75 = cc->MultiAddEvalKeys(evalMult_up_to_74, evalMultKey75, kp74.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp75.secretKey);
  auto evalSumKeys75 = cc->MultiEvalSumKeyGen(kp75.secretKey, evalSumKeysJoin_to_74, kp75.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_75 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_74, evalSumKeys75, kp75.publicKey->GetKeyTag());

  //gen keys party 76
  kp76 = cc->MultipartyKeyGen(kp75.publicKey);

  // Generate evalmult key part for party 76
  auto evalMultKey76 = cc->MultiKeySwitchGen(kp76.secretKey, kp76.secretKey, evalMult_up_to_75);
  auto evalMult_up_to_76 = cc->MultiAddEvalKeys(evalMult_up_to_75, evalMultKey76, kp75.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp76.secretKey);
  auto evalSumKeys76 = cc->MultiEvalSumKeyGen(kp76.secretKey, evalSumKeysJoin_to_75, kp76.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_76 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_75, evalSumKeys76, kp76.publicKey->GetKeyTag());

  //gen keys party 77
  kp77 = cc->MultipartyKeyGen(kp76.publicKey);

  // Generate evalmult key part for party 77
  auto evalMultKey77 = cc->MultiKeySwitchGen(kp77.secretKey, kp77.secretKey, evalMult_up_to_76);
  auto evalMult_up_to_77 = cc->MultiAddEvalKeys(evalMult_up_to_76, evalMultKey77, kp76.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp77.secretKey);
  auto evalSumKeys77 = cc->MultiEvalSumKeyGen(kp77.secretKey, evalSumKeysJoin_to_76, kp77.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_77 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_76, evalSumKeys77, kp77.publicKey->GetKeyTag());

  //gen keys party 78
  kp78 = cc->MultipartyKeyGen(kp77.publicKey);

  // Generate evalmult key part for party 78
  auto evalMultKey78 = cc->MultiKeySwitchGen(kp78.secretKey, kp78.secretKey, evalMult_up_to_77);
  auto evalMult_up_to_78 = cc->MultiAddEvalKeys(evalMult_up_to_77, evalMultKey78, kp77.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp78.secretKey);
  auto evalSumKeys78 = cc->MultiEvalSumKeyGen(kp78.secretKey, evalSumKeysJoin_to_77, kp78.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_78 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_77, evalSumKeys78, kp78.publicKey->GetKeyTag());

  //gen keys party 79
  kp79 = cc->MultipartyKeyGen(kp78.publicKey);

  // Generate evalmult key part for party 79
  auto evalMultKey79 = cc->MultiKeySwitchGen(kp79.secretKey, kp79.secretKey, evalMult_up_to_78);
  auto evalMult_up_to_79 = cc->MultiAddEvalKeys(evalMult_up_to_78, evalMultKey79, kp78.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp79.secretKey);
  auto evalSumKeys79 = cc->MultiEvalSumKeyGen(kp79.secretKey, evalSumKeysJoin_to_78, kp79.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_79 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_78, evalSumKeys79, kp79.publicKey->GetKeyTag());

  //gen keys party 80
  kp80 = cc->MultipartyKeyGen(kp79.publicKey);

  // Generate evalmult key part for party 80
  auto evalMultKey80 = cc->MultiKeySwitchGen(kp80.secretKey, kp80.secretKey, evalMult_up_to_79);
  auto evalMult_up_to_80 = cc->MultiAddEvalKeys(evalMult_up_to_79, evalMultKey80, kp79.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp80.secretKey);
  auto evalSumKeys80 = cc->MultiEvalSumKeyGen(kp80.secretKey, evalSumKeysJoin_to_79, kp80.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_80 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_79, evalSumKeys80, kp80.publicKey->GetKeyTag());

  //gen keys party 81
  kp81 = cc->MultipartyKeyGen(kp80.publicKey);

  // Generate evalmult key part for party 81
  auto evalMultKey81 = cc->MultiKeySwitchGen(kp81.secretKey, kp81.secretKey, evalMult_up_to_80);
  auto evalMult_up_to_81 = cc->MultiAddEvalKeys(evalMult_up_to_80, evalMultKey81, kp80.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp81.secretKey);
  auto evalSumKeys81 = cc->MultiEvalSumKeyGen(kp81.secretKey, evalSumKeysJoin_to_80, kp81.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_81 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_80, evalSumKeys81, kp81.publicKey->GetKeyTag());

  //gen keys party 82
  kp82 = cc->MultipartyKeyGen(kp81.publicKey);

  // Generate evalmult key part for party 82
  auto evalMultKey82 = cc->MultiKeySwitchGen(kp82.secretKey, kp82.secretKey, evalMult_up_to_81);
  auto evalMult_up_to_82 = cc->MultiAddEvalKeys(evalMult_up_to_81, evalMultKey82, kp81.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp82.secretKey);
  auto evalSumKeys82 = cc->MultiEvalSumKeyGen(kp82.secretKey, evalSumKeysJoin_to_81, kp82.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_82 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_81, evalSumKeys82, kp82.publicKey->GetKeyTag());

  //gen keys party 83
  kp83 = cc->MultipartyKeyGen(kp82.publicKey);

  // Generate evalmult key part for party 83
  auto evalMultKey83 = cc->MultiKeySwitchGen(kp83.secretKey, kp83.secretKey, evalMult_up_to_82);
  auto evalMult_up_to_83 = cc->MultiAddEvalKeys(evalMult_up_to_82, evalMultKey83, kp82.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp83.secretKey);
  auto evalSumKeys83 = cc->MultiEvalSumKeyGen(kp83.secretKey, evalSumKeysJoin_to_82, kp83.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_83 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_82, evalSumKeys83, kp83.publicKey->GetKeyTag());

  //gen keys party 84
  kp84 = cc->MultipartyKeyGen(kp83.publicKey);

  // Generate evalmult key part for party 84
  auto evalMultKey84 = cc->MultiKeySwitchGen(kp84.secretKey, kp84.secretKey, evalMult_up_to_83);
  auto evalMult_up_to_84 = cc->MultiAddEvalKeys(evalMult_up_to_83, evalMultKey84, kp83.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp84.secretKey);
  auto evalSumKeys84 = cc->MultiEvalSumKeyGen(kp84.secretKey, evalSumKeysJoin_to_83, kp84.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_84 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_83, evalSumKeys84, kp84.publicKey->GetKeyTag());

  //gen keys party 85
  kp85 = cc->MultipartyKeyGen(kp84.publicKey);

  // Generate evalmult key part for party 85
  auto evalMultKey85 = cc->MultiKeySwitchGen(kp85.secretKey, kp85.secretKey, evalMult_up_to_84);
  auto evalMult_up_to_85 = cc->MultiAddEvalKeys(evalMult_up_to_84, evalMultKey85, kp84.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp85.secretKey);
  auto evalSumKeys85 = cc->MultiEvalSumKeyGen(kp85.secretKey, evalSumKeysJoin_to_84, kp85.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_85 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_84, evalSumKeys85, kp85.publicKey->GetKeyTag());

  //gen keys party 86
  kp86 = cc->MultipartyKeyGen(kp85.publicKey);

  // Generate evalmult key part for party 86
  auto evalMultKey86 = cc->MultiKeySwitchGen(kp86.secretKey, kp86.secretKey, evalMult_up_to_85);
  auto evalMult_up_to_86 = cc->MultiAddEvalKeys(evalMult_up_to_85, evalMultKey86, kp85.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp86.secretKey);
  auto evalSumKeys86 = cc->MultiEvalSumKeyGen(kp86.secretKey, evalSumKeysJoin_to_85, kp86.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_86 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_85, evalSumKeys86, kp86.publicKey->GetKeyTag());

  //gen keys party 87
  kp87 = cc->MultipartyKeyGen(kp86.publicKey);

  // Generate evalmult key part for party 87
  auto evalMultKey87 = cc->MultiKeySwitchGen(kp87.secretKey, kp87.secretKey, evalMult_up_to_86);
  auto evalMult_up_to_87 = cc->MultiAddEvalKeys(evalMult_up_to_86, evalMultKey87, kp86.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp87.secretKey);
  auto evalSumKeys87 = cc->MultiEvalSumKeyGen(kp87.secretKey, evalSumKeysJoin_to_86, kp87.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_87 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_86, evalSumKeys87, kp87.publicKey->GetKeyTag());

  //gen keys party 88
  kp88 = cc->MultipartyKeyGen(kp87.publicKey);

  // Generate evalmult key part for party 88
  auto evalMultKey88 = cc->MultiKeySwitchGen(kp88.secretKey, kp88.secretKey, evalMult_up_to_87);
  auto evalMult_up_to_88 = cc->MultiAddEvalKeys(evalMult_up_to_87, evalMultKey88, kp87.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp88.secretKey);
  auto evalSumKeys88 = cc->MultiEvalSumKeyGen(kp88.secretKey, evalSumKeysJoin_to_87, kp88.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_88 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_87, evalSumKeys88, kp88.publicKey->GetKeyTag());

  //gen keys party 89
  kp89 = cc->MultipartyKeyGen(kp88.publicKey);

  // Generate evalmult key part for party 89
  auto evalMultKey89 = cc->MultiKeySwitchGen(kp89.secretKey, kp89.secretKey, evalMult_up_to_88);
  auto evalMult_up_to_89 = cc->MultiAddEvalKeys(evalMult_up_to_88, evalMultKey89, kp88.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp89.secretKey);
  auto evalSumKeys89 = cc->MultiEvalSumKeyGen(kp89.secretKey, evalSumKeysJoin_to_88, kp89.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_89 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_88, evalSumKeys89, kp89.publicKey->GetKeyTag());

  //gen keys party 90
  kp90 = cc->MultipartyKeyGen(kp89.publicKey);

  // Generate evalmult key part for party 90
  auto evalMultKey90 = cc->MultiKeySwitchGen(kp90.secretKey, kp90.secretKey, evalMult_up_to_89);
  auto evalMult_up_to_90 = cc->MultiAddEvalKeys(evalMult_up_to_89, evalMultKey90, kp89.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp90.secretKey);
  auto evalSumKeys90 = cc->MultiEvalSumKeyGen(kp90.secretKey, evalSumKeysJoin_to_89, kp90.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_90 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_89, evalSumKeys90, kp90.publicKey->GetKeyTag());

  //gen keys party 91
  kp91 = cc->MultipartyKeyGen(kp90.publicKey);

  // Generate evalmult key part for party 91
  auto evalMultKey91 = cc->MultiKeySwitchGen(kp91.secretKey, kp91.secretKey, evalMult_up_to_90);
  auto evalMult_up_to_91 = cc->MultiAddEvalKeys(evalMult_up_to_90, evalMultKey91, kp90.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp91.secretKey);
  auto evalSumKeys91 = cc->MultiEvalSumKeyGen(kp91.secretKey, evalSumKeysJoin_to_90, kp91.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_91 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_90, evalSumKeys91, kp91.publicKey->GetKeyTag());

  //gen keys party 92
  kp92 = cc->MultipartyKeyGen(kp91.publicKey);

  // Generate evalmult key part for party 92
  auto evalMultKey92 = cc->MultiKeySwitchGen(kp92.secretKey, kp92.secretKey, evalMult_up_to_91);
  auto evalMult_up_to_92 = cc->MultiAddEvalKeys(evalMult_up_to_91, evalMultKey92, kp91.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp92.secretKey);
  auto evalSumKeys92 = cc->MultiEvalSumKeyGen(kp92.secretKey, evalSumKeysJoin_to_91, kp92.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_92 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_91, evalSumKeys92, kp92.publicKey->GetKeyTag());

  //gen keys party 93
  kp93 = cc->MultipartyKeyGen(kp92.publicKey);

  // Generate evalmult key part for party 93
  auto evalMultKey93 = cc->MultiKeySwitchGen(kp93.secretKey, kp93.secretKey, evalMult_up_to_92);
  auto evalMult_up_to_93 = cc->MultiAddEvalKeys(evalMult_up_to_92, evalMultKey93, kp92.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp93.secretKey);
  auto evalSumKeys93 = cc->MultiEvalSumKeyGen(kp93.secretKey, evalSumKeysJoin_to_92, kp93.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_93 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_92, evalSumKeys93, kp93.publicKey->GetKeyTag());

  //gen keys party 94
  kp94 = cc->MultipartyKeyGen(kp93.publicKey);

  // Generate evalmult key part for party 94
  auto evalMultKey94 = cc->MultiKeySwitchGen(kp94.secretKey, kp94.secretKey, evalMult_up_to_93);
  auto evalMult_up_to_94 = cc->MultiAddEvalKeys(evalMult_up_to_93, evalMultKey94, kp93.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp94.secretKey);
  auto evalSumKeys94 = cc->MultiEvalSumKeyGen(kp94.secretKey, evalSumKeysJoin_to_93, kp94.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_94 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_93, evalSumKeys94, kp94.publicKey->GetKeyTag());

  //gen keys party 95
  kp95 = cc->MultipartyKeyGen(kp94.publicKey);

  // Generate evalmult key part for party 95
  auto evalMultKey95 = cc->MultiKeySwitchGen(kp95.secretKey, kp95.secretKey, evalMult_up_to_94);
  auto evalMult_up_to_95 = cc->MultiAddEvalKeys(evalMult_up_to_94, evalMultKey95, kp94.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp95.secretKey);
  auto evalSumKeys95 = cc->MultiEvalSumKeyGen(kp95.secretKey, evalSumKeysJoin_to_94, kp95.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_95 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_94, evalSumKeys95, kp95.publicKey->GetKeyTag());

  //gen keys party 96
  kp96 = cc->MultipartyKeyGen(kp95.publicKey);

  // Generate evalmult key part for party 96
  auto evalMultKey96 = cc->MultiKeySwitchGen(kp96.secretKey, kp96.secretKey, evalMult_up_to_95);
  auto evalMult_up_to_96 = cc->MultiAddEvalKeys(evalMult_up_to_95, evalMultKey96, kp95.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp96.secretKey);
  auto evalSumKeys96 = cc->MultiEvalSumKeyGen(kp96.secretKey, evalSumKeysJoin_to_95, kp96.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_96 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_95, evalSumKeys96, kp96.publicKey->GetKeyTag());

  //gen keys party 97
  kp97 = cc->MultipartyKeyGen(kp96.publicKey);

  // Generate evalmult key part for party 97
  auto evalMultKey97 = cc->MultiKeySwitchGen(kp97.secretKey, kp97.secretKey, evalMult_up_to_96);
  auto evalMult_up_to_97 = cc->MultiAddEvalKeys(evalMult_up_to_96, evalMultKey97, kp96.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp97.secretKey);
  auto evalSumKeys97 = cc->MultiEvalSumKeyGen(kp97.secretKey, evalSumKeysJoin_to_96, kp97.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_97 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_96, evalSumKeys97, kp97.publicKey->GetKeyTag());

  //gen keys party 98
  kp98 = cc->MultipartyKeyGen(kp97.publicKey);

  // Generate evalmult key part for party 98
  auto evalMultKey98 = cc->MultiKeySwitchGen(kp98.secretKey, kp98.secretKey, evalMult_up_to_97);
  auto evalMult_up_to_98 = cc->MultiAddEvalKeys(evalMult_up_to_97, evalMultKey98, kp97.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp98.secretKey);
  auto evalSumKeys98 = cc->MultiEvalSumKeyGen(kp98.secretKey, evalSumKeysJoin_to_97, kp98.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_98 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_97, evalSumKeys98, kp98.publicKey->GetKeyTag());

  //gen keys party 99
  kp99 = cc->MultipartyKeyGen(kp98.publicKey);

  // Generate evalmult key part for party 99
  auto evalMultKey99 = cc->MultiKeySwitchGen(kp99.secretKey, kp99.secretKey, evalMult_up_to_98);
  auto evalMult_up_to_99 = cc->MultiAddEvalKeys(evalMult_up_to_98, evalMultKey99, kp98.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp99.secretKey);
  auto evalSumKeys99 = cc->MultiEvalSumKeyGen(kp99.secretKey, evalSumKeysJoin_to_98, kp99.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_99 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_98, evalSumKeys99, kp99.publicKey->GetKeyTag());

  //gen keys party 100
  kp100 = cc->MultipartyKeyGen(kp99.publicKey);

  // Generate evalmult key part for party 100
  auto evalMultKey100 = cc->MultiKeySwitchGen(kp100.secretKey, kp100.secretKey, evalMult_up_to_99);
  auto evalMult_up_to_100 = cc->MultiAddEvalKeys(evalMult_up_to_99, evalMultKey100, kp99.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp100.secretKey);
  auto evalSumKeys100 = cc->MultiEvalSumKeyGen(kp100.secretKey, evalSumKeysJoin_to_99, kp100.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_100 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_99, evalSumKeys100, kp100.publicKey->GetKeyTag());

  //gen keys party 101
  kp101 = cc->MultipartyKeyGen(kp100.publicKey);

  // Generate evalmult key part for party 101
  auto evalMultKey101 = cc->MultiKeySwitchGen(kp101.secretKey, kp101.secretKey, evalMult_up_to_100);
  auto evalMult_up_to_101 = cc->MultiAddEvalKeys(evalMult_up_to_100, evalMultKey101, kp100.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp101.secretKey);
  auto evalSumKeys101 = cc->MultiEvalSumKeyGen(kp101.secretKey, evalSumKeysJoin_to_100, kp101.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_101 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_100, evalSumKeys101, kp101.publicKey->GetKeyTag());

  //gen keys party 102
  kp102 = cc->MultipartyKeyGen(kp101.publicKey);

  // Generate evalmult key part for party 102
  auto evalMultKey102 = cc->MultiKeySwitchGen(kp102.secretKey, kp102.secretKey, evalMult_up_to_101);
  auto evalMult_up_to_102 = cc->MultiAddEvalKeys(evalMult_up_to_101, evalMultKey102, kp101.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp102.secretKey);
  auto evalSumKeys102 = cc->MultiEvalSumKeyGen(kp102.secretKey, evalSumKeysJoin_to_101, kp102.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_102 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_101, evalSumKeys102, kp102.publicKey->GetKeyTag());

  //gen keys party 103
  kp103 = cc->MultipartyKeyGen(kp102.publicKey);

  // Generate evalmult key part for party 103
  auto evalMultKey103 = cc->MultiKeySwitchGen(kp103.secretKey, kp103.secretKey, evalMult_up_to_102);
  auto evalMult_up_to_103 = cc->MultiAddEvalKeys(evalMult_up_to_102, evalMultKey103, kp102.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp103.secretKey);
  auto evalSumKeys103 = cc->MultiEvalSumKeyGen(kp103.secretKey, evalSumKeysJoin_to_102, kp103.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_103 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_102, evalSumKeys103, kp103.publicKey->GetKeyTag());

  //gen keys party 104
  kp104 = cc->MultipartyKeyGen(kp103.publicKey);

  // Generate evalmult key part for party 104
  auto evalMultKey104 = cc->MultiKeySwitchGen(kp104.secretKey, kp104.secretKey, evalMult_up_to_103);
  auto evalMult_up_to_104 = cc->MultiAddEvalKeys(evalMult_up_to_103, evalMultKey104, kp103.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp104.secretKey);
  auto evalSumKeys104 = cc->MultiEvalSumKeyGen(kp104.secretKey, evalSumKeysJoin_to_103, kp104.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_104 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_103, evalSumKeys104, kp104.publicKey->GetKeyTag());

  //gen keys party 105
  kp105 = cc->MultipartyKeyGen(kp104.publicKey);

  // Generate evalmult key part for party 105
  auto evalMultKey105 = cc->MultiKeySwitchGen(kp105.secretKey, kp105.secretKey, evalMult_up_to_104);
  auto evalMult_up_to_105 = cc->MultiAddEvalKeys(evalMult_up_to_104, evalMultKey105, kp104.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp105.secretKey);
  auto evalSumKeys105 = cc->MultiEvalSumKeyGen(kp105.secretKey, evalSumKeysJoin_to_104, kp105.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_105 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_104, evalSumKeys105, kp105.publicKey->GetKeyTag());

  //gen keys party 106
  kp106 = cc->MultipartyKeyGen(kp105.publicKey);

  // Generate evalmult key part for party 106
  auto evalMultKey106 = cc->MultiKeySwitchGen(kp106.secretKey, kp106.secretKey, evalMult_up_to_105);
  auto evalMult_up_to_106 = cc->MultiAddEvalKeys(evalMult_up_to_105, evalMultKey106, kp105.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp106.secretKey);
  auto evalSumKeys106 = cc->MultiEvalSumKeyGen(kp106.secretKey, evalSumKeysJoin_to_105, kp106.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_106 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_105, evalSumKeys106, kp106.publicKey->GetKeyTag());

  //gen keys party 107
  kp107 = cc->MultipartyKeyGen(kp106.publicKey);

  // Generate evalmult key part for party 107
  auto evalMultKey107 = cc->MultiKeySwitchGen(kp107.secretKey, kp107.secretKey, evalMult_up_to_106);
  auto evalMult_up_to_107 = cc->MultiAddEvalKeys(evalMult_up_to_106, evalMultKey107, kp106.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp107.secretKey);
  auto evalSumKeys107 = cc->MultiEvalSumKeyGen(kp107.secretKey, evalSumKeysJoin_to_106, kp107.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_107 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_106, evalSumKeys107, kp107.publicKey->GetKeyTag());

  //gen keys party 108
  kp108 = cc->MultipartyKeyGen(kp107.publicKey);

  // Generate evalmult key part for party 108
  auto evalMultKey108 = cc->MultiKeySwitchGen(kp108.secretKey, kp108.secretKey, evalMult_up_to_107);
  auto evalMult_up_to_108 = cc->MultiAddEvalKeys(evalMult_up_to_107, evalMultKey108, kp107.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp108.secretKey);
  auto evalSumKeys108 = cc->MultiEvalSumKeyGen(kp108.secretKey, evalSumKeysJoin_to_107, kp108.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_108 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_107, evalSumKeys108, kp108.publicKey->GetKeyTag());

  //gen keys party 109
  kp109 = cc->MultipartyKeyGen(kp108.publicKey);

  // Generate evalmult key part for party 109
  auto evalMultKey109 = cc->MultiKeySwitchGen(kp109.secretKey, kp109.secretKey, evalMult_up_to_108);
  auto evalMult_up_to_109 = cc->MultiAddEvalKeys(evalMult_up_to_108, evalMultKey109, kp108.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp109.secretKey);
  auto evalSumKeys109 = cc->MultiEvalSumKeyGen(kp109.secretKey, evalSumKeysJoin_to_108, kp109.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_109 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_108, evalSumKeys109, kp109.publicKey->GetKeyTag());

  //gen keys party 110
  kp110 = cc->MultipartyKeyGen(kp109.publicKey);

  // Generate evalmult key part for party 110
  auto evalMultKey110 = cc->MultiKeySwitchGen(kp110.secretKey, kp110.secretKey, evalMult_up_to_109);
  auto evalMult_up_to_110 = cc->MultiAddEvalKeys(evalMult_up_to_109, evalMultKey110, kp109.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp110.secretKey);
  auto evalSumKeys110 = cc->MultiEvalSumKeyGen(kp110.secretKey, evalSumKeysJoin_to_109, kp110.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_110 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_109, evalSumKeys110, kp110.publicKey->GetKeyTag());

  //gen keys party 111
  kp111 = cc->MultipartyKeyGen(kp110.publicKey);

  // Generate evalmult key part for party 111
  auto evalMultKey111 = cc->MultiKeySwitchGen(kp111.secretKey, kp111.secretKey, evalMult_up_to_110);
  auto evalMult_up_to_111 = cc->MultiAddEvalKeys(evalMult_up_to_110, evalMultKey111, kp110.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp111.secretKey);
  auto evalSumKeys111 = cc->MultiEvalSumKeyGen(kp111.secretKey, evalSumKeysJoin_to_110, kp111.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_111 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_110, evalSumKeys111, kp111.publicKey->GetKeyTag());

  //gen keys party 112
  kp112 = cc->MultipartyKeyGen(kp111.publicKey);

  // Generate evalmult key part for party 112
  auto evalMultKey112 = cc->MultiKeySwitchGen(kp112.secretKey, kp112.secretKey, evalMult_up_to_111);
  auto evalMult_up_to_112 = cc->MultiAddEvalKeys(evalMult_up_to_111, evalMultKey112, kp111.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp112.secretKey);
  auto evalSumKeys112 = cc->MultiEvalSumKeyGen(kp112.secretKey, evalSumKeysJoin_to_111, kp112.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_112 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_111, evalSumKeys112, kp112.publicKey->GetKeyTag());

  //gen keys party 113
  kp113 = cc->MultipartyKeyGen(kp112.publicKey);

  // Generate evalmult key part for party 113
  auto evalMultKey113 = cc->MultiKeySwitchGen(kp113.secretKey, kp113.secretKey, evalMult_up_to_112);
  auto evalMult_up_to_113 = cc->MultiAddEvalKeys(evalMult_up_to_112, evalMultKey113, kp112.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp113.secretKey);
  auto evalSumKeys113 = cc->MultiEvalSumKeyGen(kp113.secretKey, evalSumKeysJoin_to_112, kp113.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_113 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_112, evalSumKeys113, kp113.publicKey->GetKeyTag());

  //gen keys party 114
  kp114 = cc->MultipartyKeyGen(kp113.publicKey);

  // Generate evalmult key part for party 114
  auto evalMultKey114 = cc->MultiKeySwitchGen(kp114.secretKey, kp114.secretKey, evalMult_up_to_113);
  auto evalMult_up_to_114 = cc->MultiAddEvalKeys(evalMult_up_to_113, evalMultKey114, kp113.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp114.secretKey);
  auto evalSumKeys114 = cc->MultiEvalSumKeyGen(kp114.secretKey, evalSumKeysJoin_to_113, kp114.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_114 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_113, evalSumKeys114, kp114.publicKey->GetKeyTag());

  //gen keys party 115
  kp115 = cc->MultipartyKeyGen(kp114.publicKey);

  // Generate evalmult key part for party 115
  auto evalMultKey115 = cc->MultiKeySwitchGen(kp115.secretKey, kp115.secretKey, evalMult_up_to_114);
  auto evalMult_up_to_115 = cc->MultiAddEvalKeys(evalMult_up_to_114, evalMultKey115, kp114.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp115.secretKey);
  auto evalSumKeys115 = cc->MultiEvalSumKeyGen(kp115.secretKey, evalSumKeysJoin_to_114, kp115.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_115 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_114, evalSumKeys115, kp115.publicKey->GetKeyTag());

  //gen keys party 116
  kp116 = cc->MultipartyKeyGen(kp115.publicKey);

  // Generate evalmult key part for party 116
  auto evalMultKey116 = cc->MultiKeySwitchGen(kp116.secretKey, kp116.secretKey, evalMult_up_to_115);
  auto evalMult_up_to_116 = cc->MultiAddEvalKeys(evalMult_up_to_115, evalMultKey116, kp115.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp116.secretKey);
  auto evalSumKeys116 = cc->MultiEvalSumKeyGen(kp116.secretKey, evalSumKeysJoin_to_115, kp116.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_116 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_115, evalSumKeys116, kp116.publicKey->GetKeyTag());

  //gen keys party 117
  kp117 = cc->MultipartyKeyGen(kp116.publicKey);

  // Generate evalmult key part for party 117
  auto evalMultKey117 = cc->MultiKeySwitchGen(kp117.secretKey, kp117.secretKey, evalMult_up_to_116);
  auto evalMult_up_to_117 = cc->MultiAddEvalKeys(evalMult_up_to_116, evalMultKey117, kp116.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp117.secretKey);
  auto evalSumKeys117 = cc->MultiEvalSumKeyGen(kp117.secretKey, evalSumKeysJoin_to_116, kp117.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_117 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_116, evalSumKeys117, kp117.publicKey->GetKeyTag());

  //gen keys party 118
  kp118 = cc->MultipartyKeyGen(kp117.publicKey);

  // Generate evalmult key part for party 118
  auto evalMultKey118 = cc->MultiKeySwitchGen(kp118.secretKey, kp118.secretKey, evalMult_up_to_117);
  auto evalMult_up_to_118 = cc->MultiAddEvalKeys(evalMult_up_to_117, evalMultKey118, kp117.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp118.secretKey);
  auto evalSumKeys118 = cc->MultiEvalSumKeyGen(kp118.secretKey, evalSumKeysJoin_to_117, kp118.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_118 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_117, evalSumKeys118, kp118.publicKey->GetKeyTag());

  //gen keys party 119
  kp119 = cc->MultipartyKeyGen(kp118.publicKey);

  // Generate evalmult key part for party 119
  auto evalMultKey119 = cc->MultiKeySwitchGen(kp119.secretKey, kp119.secretKey, evalMult_up_to_118);
  auto evalMult_up_to_119 = cc->MultiAddEvalKeys(evalMult_up_to_118, evalMultKey119, kp118.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp119.secretKey);
  auto evalSumKeys119 = cc->MultiEvalSumKeyGen(kp119.secretKey, evalSumKeysJoin_to_118, kp119.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_119 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_118, evalSumKeys119, kp119.publicKey->GetKeyTag());

  //gen keys party 120
  kp120 = cc->MultipartyKeyGen(kp119.publicKey);

  // Generate evalmult key part for party 120
  auto evalMultKey120 = cc->MultiKeySwitchGen(kp120.secretKey, kp120.secretKey, evalMult_up_to_119);
  auto evalMult_up_to_120 = cc->MultiAddEvalKeys(evalMult_up_to_119, evalMultKey120, kp119.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp120.secretKey);
  auto evalSumKeys120 = cc->MultiEvalSumKeyGen(kp120.secretKey, evalSumKeysJoin_to_119, kp120.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_120 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_119, evalSumKeys120, kp120.publicKey->GetKeyTag());

  //gen keys party 121
  kp121 = cc->MultipartyKeyGen(kp120.publicKey);

  // Generate evalmult key part for party 121
  auto evalMultKey121 = cc->MultiKeySwitchGen(kp121.secretKey, kp121.secretKey, evalMult_up_to_120);
  auto evalMult_up_to_121 = cc->MultiAddEvalKeys(evalMult_up_to_120, evalMultKey121, kp120.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp121.secretKey);
  auto evalSumKeys121 = cc->MultiEvalSumKeyGen(kp121.secretKey, evalSumKeysJoin_to_120, kp121.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_121 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_120, evalSumKeys121, kp121.publicKey->GetKeyTag());

  //gen keys party 122
  kp122 = cc->MultipartyKeyGen(kp121.publicKey);

  // Generate evalmult key part for party 122
  auto evalMultKey122 = cc->MultiKeySwitchGen(kp122.secretKey, kp122.secretKey, evalMult_up_to_121);
  auto evalMult_up_to_122 = cc->MultiAddEvalKeys(evalMult_up_to_121, evalMultKey122, kp121.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp122.secretKey);
  auto evalSumKeys122 = cc->MultiEvalSumKeyGen(kp122.secretKey, evalSumKeysJoin_to_121, kp122.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_122 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_121, evalSumKeys122, kp122.publicKey->GetKeyTag());

  //gen keys party 123
  kp123 = cc->MultipartyKeyGen(kp122.publicKey);

  // Generate evalmult key part for party 123
  auto evalMultKey123 = cc->MultiKeySwitchGen(kp123.secretKey, kp123.secretKey, evalMult_up_to_122);
  auto evalMult_up_to_123 = cc->MultiAddEvalKeys(evalMult_up_to_122, evalMultKey123, kp122.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp123.secretKey);
  auto evalSumKeys123 = cc->MultiEvalSumKeyGen(kp123.secretKey, evalSumKeysJoin_to_122, kp123.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_123 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_122, evalSumKeys123, kp123.publicKey->GetKeyTag());

  //gen keys party 124
  kp124 = cc->MultipartyKeyGen(kp123.publicKey);

  // Generate evalmult key part for party 124
  auto evalMultKey124 = cc->MultiKeySwitchGen(kp124.secretKey, kp124.secretKey, evalMult_up_to_123);
  auto evalMult_up_to_124 = cc->MultiAddEvalKeys(evalMult_up_to_123, evalMultKey124, kp123.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp124.secretKey);
  auto evalSumKeys124 = cc->MultiEvalSumKeyGen(kp124.secretKey, evalSumKeysJoin_to_123, kp124.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_124 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_123, evalSumKeys124, kp124.publicKey->GetKeyTag());

  //gen keys party 125
  kp125 = cc->MultipartyKeyGen(kp124.publicKey);

  // Generate evalmult key part for party 125
  auto evalMultKey125 = cc->MultiKeySwitchGen(kp125.secretKey, kp125.secretKey, evalMult_up_to_124);
  auto evalMult_up_to_125 = cc->MultiAddEvalKeys(evalMult_up_to_124, evalMultKey125, kp124.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp125.secretKey);
  auto evalSumKeys125 = cc->MultiEvalSumKeyGen(kp125.secretKey, evalSumKeysJoin_to_124, kp125.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_125 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_124, evalSumKeys125, kp125.publicKey->GetKeyTag());

  //gen keys party 126
  kp126 = cc->MultipartyKeyGen(kp125.publicKey);

  // Generate evalmult key part for party 126
  auto evalMultKey126 = cc->MultiKeySwitchGen(kp126.secretKey, kp126.secretKey, evalMult_up_to_125);
  auto evalMult_up_to_126 = cc->MultiAddEvalKeys(evalMult_up_to_125, evalMultKey126, kp125.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp126.secretKey);
  auto evalSumKeys126 = cc->MultiEvalSumKeyGen(kp126.secretKey, evalSumKeysJoin_to_125, kp126.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_126 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_125, evalSumKeys126, kp126.publicKey->GetKeyTag());

  //gen keys party 127
  kp127 = cc->MultipartyKeyGen(kp126.publicKey);

  // Generate evalmult key part for party 127
  auto evalMultKey127 = cc->MultiKeySwitchGen(kp127.secretKey, kp127.secretKey, evalMult_up_to_126);
  auto evalMult_up_to_127 = cc->MultiAddEvalKeys(evalMult_up_to_126, evalMultKey127, kp126.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp127.secretKey);
  auto evalSumKeys127 = cc->MultiEvalSumKeyGen(kp127.secretKey, evalSumKeysJoin_to_126, kp127.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_127 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_126, evalSumKeys127, kp127.publicKey->GetKeyTag());

  //gen keys party 128
  kp128 = cc->MultipartyKeyGen(kp127.publicKey);

  // Generate evalmult key part for party 128
  auto evalMultKey128 = cc->MultiKeySwitchGen(kp128.secretKey, kp128.secretKey, evalMult_up_to_127);
  auto evalMult_up_to_128 = cc->MultiAddEvalKeys(evalMult_up_to_127, evalMultKey128, kp127.publicKey->GetKeyTag());

  // gen eval sum keys
  cc->EvalSumKeyGen(kp128.secretKey);
  auto evalSumKeys128 = cc->MultiEvalSumKeyGen(kp128.secretKey, evalSumKeysJoin_to_127, kp128.publicKey->GetKeyTag());
  auto evalSumKeysJoin_to_128 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_127, evalSumKeys128, kp128.publicKey->GetKeyTag());
  auto evalMultJoint1 = cc->MultiMultEvalKey(evalMult_up_to_128, kp1.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultJoint2 = cc->MultiMultEvalKey(evalMult_up_to_128, kp2.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial2 = cc->MultiAddEvalMultKeys(evalMultJoint1, evalMultJoint2, kp128.publicKey->GetKeyTag());
  auto evalMultJoint3 = cc->MultiMultEvalKey(evalMult_up_to_128, kp3.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial3 = cc->MultiAddEvalMultKeys(evalMultJoint2, evalMultJoint3, kp128.publicKey->GetKeyTag());
  auto evalMultJoint4 = cc->MultiMultEvalKey(evalMult_up_to_128, kp4.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial4 = cc->MultiAddEvalMultKeys(evalMultJoint3, evalMultJoint4, kp128.publicKey->GetKeyTag());
  auto evalMultJoint5 = cc->MultiMultEvalKey(evalMult_up_to_128, kp5.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial5 = cc->MultiAddEvalMultKeys(evalMultJoint4, evalMultJoint5, kp128.publicKey->GetKeyTag());
  auto evalMultJoint6 = cc->MultiMultEvalKey(evalMult_up_to_128, kp6.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial6 = cc->MultiAddEvalMultKeys(evalMultJoint5, evalMultJoint6, kp128.publicKey->GetKeyTag());
  auto evalMultJoint7 = cc->MultiMultEvalKey(evalMult_up_to_128, kp7.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial7 = cc->MultiAddEvalMultKeys(evalMultJoint6, evalMultJoint7, kp128.publicKey->GetKeyTag());
  auto evalMultJoint8 = cc->MultiMultEvalKey(evalMult_up_to_128, kp8.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial8 = cc->MultiAddEvalMultKeys(evalMultJoint7, evalMultJoint8, kp128.publicKey->GetKeyTag());
  auto evalMultJoint9 = cc->MultiMultEvalKey(evalMult_up_to_128, kp9.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial9 = cc->MultiAddEvalMultKeys(evalMultJoint8, evalMultJoint9, kp128.publicKey->GetKeyTag());
  auto evalMultJoint10 = cc->MultiMultEvalKey(evalMult_up_to_128, kp10.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial10 = cc->MultiAddEvalMultKeys(evalMultJoint9, evalMultJoint10, kp128.publicKey->GetKeyTag());
  auto evalMultJoint11 = cc->MultiMultEvalKey(evalMult_up_to_128, kp11.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial11 = cc->MultiAddEvalMultKeys(evalMultJoint10, evalMultJoint11, kp128.publicKey->GetKeyTag());
  auto evalMultJoint12 = cc->MultiMultEvalKey(evalMult_up_to_128, kp12.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial12 = cc->MultiAddEvalMultKeys(evalMultJoint11, evalMultJoint12, kp128.publicKey->GetKeyTag());
  auto evalMultJoint13 = cc->MultiMultEvalKey(evalMult_up_to_128, kp13.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial13 = cc->MultiAddEvalMultKeys(evalMultJoint12, evalMultJoint13, kp128.publicKey->GetKeyTag());
  auto evalMultJoint14 = cc->MultiMultEvalKey(evalMult_up_to_128, kp14.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial14 = cc->MultiAddEvalMultKeys(evalMultJoint13, evalMultJoint14, kp128.publicKey->GetKeyTag());
  auto evalMultJoint15 = cc->MultiMultEvalKey(evalMult_up_to_128, kp15.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial15 = cc->MultiAddEvalMultKeys(evalMultJoint14, evalMultJoint15, kp128.publicKey->GetKeyTag());
  auto evalMultJoint16 = cc->MultiMultEvalKey(evalMult_up_to_128, kp16.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial16 = cc->MultiAddEvalMultKeys(evalMultJoint15, evalMultJoint16, kp128.publicKey->GetKeyTag());
  auto evalMultJoint17 = cc->MultiMultEvalKey(evalMult_up_to_128, kp17.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial17 = cc->MultiAddEvalMultKeys(evalMultJoint16, evalMultJoint17, kp128.publicKey->GetKeyTag());
  auto evalMultJoint18 = cc->MultiMultEvalKey(evalMult_up_to_128, kp18.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial18 = cc->MultiAddEvalMultKeys(evalMultJoint17, evalMultJoint18, kp128.publicKey->GetKeyTag());
  auto evalMultJoint19 = cc->MultiMultEvalKey(evalMult_up_to_128, kp19.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial19 = cc->MultiAddEvalMultKeys(evalMultJoint18, evalMultJoint19, kp128.publicKey->GetKeyTag());
  auto evalMultJoint20 = cc->MultiMultEvalKey(evalMult_up_to_128, kp20.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial20 = cc->MultiAddEvalMultKeys(evalMultJoint19, evalMultJoint20, kp128.publicKey->GetKeyTag());
  auto evalMultJoint21 = cc->MultiMultEvalKey(evalMult_up_to_128, kp21.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial21 = cc->MultiAddEvalMultKeys(evalMultJoint20, evalMultJoint21, kp128.publicKey->GetKeyTag());
  auto evalMultJoint22 = cc->MultiMultEvalKey(evalMult_up_to_128, kp22.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial22 = cc->MultiAddEvalMultKeys(evalMultJoint21, evalMultJoint22, kp128.publicKey->GetKeyTag());
  auto evalMultJoint23 = cc->MultiMultEvalKey(evalMult_up_to_128, kp23.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial23 = cc->MultiAddEvalMultKeys(evalMultJoint22, evalMultJoint23, kp128.publicKey->GetKeyTag());
  auto evalMultJoint24 = cc->MultiMultEvalKey(evalMult_up_to_128, kp24.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial24 = cc->MultiAddEvalMultKeys(evalMultJoint23, evalMultJoint24, kp128.publicKey->GetKeyTag());
  auto evalMultJoint25 = cc->MultiMultEvalKey(evalMult_up_to_128, kp25.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial25 = cc->MultiAddEvalMultKeys(evalMultJoint24, evalMultJoint25, kp128.publicKey->GetKeyTag());
  auto evalMultJoint26 = cc->MultiMultEvalKey(evalMult_up_to_128, kp26.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial26 = cc->MultiAddEvalMultKeys(evalMultJoint25, evalMultJoint26, kp128.publicKey->GetKeyTag());
  auto evalMultJoint27 = cc->MultiMultEvalKey(evalMult_up_to_128, kp27.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial27 = cc->MultiAddEvalMultKeys(evalMultJoint26, evalMultJoint27, kp128.publicKey->GetKeyTag());
  auto evalMultJoint28 = cc->MultiMultEvalKey(evalMult_up_to_128, kp28.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial28 = cc->MultiAddEvalMultKeys(evalMultJoint27, evalMultJoint28, kp128.publicKey->GetKeyTag());
  auto evalMultJoint29 = cc->MultiMultEvalKey(evalMult_up_to_128, kp29.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial29 = cc->MultiAddEvalMultKeys(evalMultJoint28, evalMultJoint29, kp128.publicKey->GetKeyTag());
  auto evalMultJoint30 = cc->MultiMultEvalKey(evalMult_up_to_128, kp30.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial30 = cc->MultiAddEvalMultKeys(evalMultJoint29, evalMultJoint30, kp128.publicKey->GetKeyTag());
  auto evalMultJoint31 = cc->MultiMultEvalKey(evalMult_up_to_128, kp31.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial31 = cc->MultiAddEvalMultKeys(evalMultJoint30, evalMultJoint31, kp128.publicKey->GetKeyTag());
  auto evalMultJoint32 = cc->MultiMultEvalKey(evalMult_up_to_128, kp32.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial32 = cc->MultiAddEvalMultKeys(evalMultJoint31, evalMultJoint32, kp128.publicKey->GetKeyTag());
  auto evalMultJoint33 = cc->MultiMultEvalKey(evalMult_up_to_128, kp33.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial33 = cc->MultiAddEvalMultKeys(evalMultJoint32, evalMultJoint33, kp128.publicKey->GetKeyTag());
  auto evalMultJoint34 = cc->MultiMultEvalKey(evalMult_up_to_128, kp34.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial34 = cc->MultiAddEvalMultKeys(evalMultJoint33, evalMultJoint34, kp128.publicKey->GetKeyTag());
  auto evalMultJoint35 = cc->MultiMultEvalKey(evalMult_up_to_128, kp35.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial35 = cc->MultiAddEvalMultKeys(evalMultJoint34, evalMultJoint35, kp128.publicKey->GetKeyTag());
  auto evalMultJoint36 = cc->MultiMultEvalKey(evalMult_up_to_128, kp36.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial36 = cc->MultiAddEvalMultKeys(evalMultJoint35, evalMultJoint36, kp128.publicKey->GetKeyTag());
  auto evalMultJoint37 = cc->MultiMultEvalKey(evalMult_up_to_128, kp37.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial37 = cc->MultiAddEvalMultKeys(evalMultJoint36, evalMultJoint37, kp128.publicKey->GetKeyTag());
  auto evalMultJoint38 = cc->MultiMultEvalKey(evalMult_up_to_128, kp38.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial38 = cc->MultiAddEvalMultKeys(evalMultJoint37, evalMultJoint38, kp128.publicKey->GetKeyTag());
  auto evalMultJoint39 = cc->MultiMultEvalKey(evalMult_up_to_128, kp39.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial39 = cc->MultiAddEvalMultKeys(evalMultJoint38, evalMultJoint39, kp128.publicKey->GetKeyTag());
  auto evalMultJoint40 = cc->MultiMultEvalKey(evalMult_up_to_128, kp40.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial40 = cc->MultiAddEvalMultKeys(evalMultJoint39, evalMultJoint40, kp128.publicKey->GetKeyTag());
  auto evalMultJoint41 = cc->MultiMultEvalKey(evalMult_up_to_128, kp41.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial41 = cc->MultiAddEvalMultKeys(evalMultJoint40, evalMultJoint41, kp128.publicKey->GetKeyTag());
  auto evalMultJoint42 = cc->MultiMultEvalKey(evalMult_up_to_128, kp42.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial42 = cc->MultiAddEvalMultKeys(evalMultJoint41, evalMultJoint42, kp128.publicKey->GetKeyTag());
  auto evalMultJoint43 = cc->MultiMultEvalKey(evalMult_up_to_128, kp43.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial43 = cc->MultiAddEvalMultKeys(evalMultJoint42, evalMultJoint43, kp128.publicKey->GetKeyTag());
  auto evalMultJoint44 = cc->MultiMultEvalKey(evalMult_up_to_128, kp44.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial44 = cc->MultiAddEvalMultKeys(evalMultJoint43, evalMultJoint44, kp128.publicKey->GetKeyTag());
  auto evalMultJoint45 = cc->MultiMultEvalKey(evalMult_up_to_128, kp45.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial45 = cc->MultiAddEvalMultKeys(evalMultJoint44, evalMultJoint45, kp128.publicKey->GetKeyTag());
  auto evalMultJoint46 = cc->MultiMultEvalKey(evalMult_up_to_128, kp46.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial46 = cc->MultiAddEvalMultKeys(evalMultJoint45, evalMultJoint46, kp128.publicKey->GetKeyTag());
  auto evalMultJoint47 = cc->MultiMultEvalKey(evalMult_up_to_128, kp47.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial47 = cc->MultiAddEvalMultKeys(evalMultJoint46, evalMultJoint47, kp128.publicKey->GetKeyTag());
  auto evalMultJoint48 = cc->MultiMultEvalKey(evalMult_up_to_128, kp48.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial48 = cc->MultiAddEvalMultKeys(evalMultJoint47, evalMultJoint48, kp128.publicKey->GetKeyTag());
  auto evalMultJoint49 = cc->MultiMultEvalKey(evalMult_up_to_128, kp49.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial49 = cc->MultiAddEvalMultKeys(evalMultJoint48, evalMultJoint49, kp128.publicKey->GetKeyTag());
  auto evalMultJoint50 = cc->MultiMultEvalKey(evalMult_up_to_128, kp50.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial50 = cc->MultiAddEvalMultKeys(evalMultJoint49, evalMultJoint50, kp128.publicKey->GetKeyTag());
  auto evalMultJoint51 = cc->MultiMultEvalKey(evalMult_up_to_128, kp51.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial51 = cc->MultiAddEvalMultKeys(evalMultJoint50, evalMultJoint51, kp128.publicKey->GetKeyTag());
  auto evalMultJoint52 = cc->MultiMultEvalKey(evalMult_up_to_128, kp52.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial52 = cc->MultiAddEvalMultKeys(evalMultJoint51, evalMultJoint52, kp128.publicKey->GetKeyTag());
  auto evalMultJoint53 = cc->MultiMultEvalKey(evalMult_up_to_128, kp53.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial53 = cc->MultiAddEvalMultKeys(evalMultJoint52, evalMultJoint53, kp128.publicKey->GetKeyTag());
  auto evalMultJoint54 = cc->MultiMultEvalKey(evalMult_up_to_128, kp54.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial54 = cc->MultiAddEvalMultKeys(evalMultJoint53, evalMultJoint54, kp128.publicKey->GetKeyTag());
  auto evalMultJoint55 = cc->MultiMultEvalKey(evalMult_up_to_128, kp55.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial55 = cc->MultiAddEvalMultKeys(evalMultJoint54, evalMultJoint55, kp128.publicKey->GetKeyTag());
  auto evalMultJoint56 = cc->MultiMultEvalKey(evalMult_up_to_128, kp56.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial56 = cc->MultiAddEvalMultKeys(evalMultJoint55, evalMultJoint56, kp128.publicKey->GetKeyTag());
  auto evalMultJoint57 = cc->MultiMultEvalKey(evalMult_up_to_128, kp57.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial57 = cc->MultiAddEvalMultKeys(evalMultJoint56, evalMultJoint57, kp128.publicKey->GetKeyTag());
  auto evalMultJoint58 = cc->MultiMultEvalKey(evalMult_up_to_128, kp58.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial58 = cc->MultiAddEvalMultKeys(evalMultJoint57, evalMultJoint58, kp128.publicKey->GetKeyTag());
  auto evalMultJoint59 = cc->MultiMultEvalKey(evalMult_up_to_128, kp59.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial59 = cc->MultiAddEvalMultKeys(evalMultJoint58, evalMultJoint59, kp128.publicKey->GetKeyTag());
  auto evalMultJoint60 = cc->MultiMultEvalKey(evalMult_up_to_128, kp60.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial60 = cc->MultiAddEvalMultKeys(evalMultJoint59, evalMultJoint60, kp128.publicKey->GetKeyTag());
  auto evalMultJoint61 = cc->MultiMultEvalKey(evalMult_up_to_128, kp61.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial61 = cc->MultiAddEvalMultKeys(evalMultJoint60, evalMultJoint61, kp128.publicKey->GetKeyTag());
  auto evalMultJoint62 = cc->MultiMultEvalKey(evalMult_up_to_128, kp62.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial62 = cc->MultiAddEvalMultKeys(evalMultJoint61, evalMultJoint62, kp128.publicKey->GetKeyTag());
  auto evalMultJoint63 = cc->MultiMultEvalKey(evalMult_up_to_128, kp63.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial63 = cc->MultiAddEvalMultKeys(evalMultJoint62, evalMultJoint63, kp128.publicKey->GetKeyTag());
  auto evalMultJoint64 = cc->MultiMultEvalKey(evalMult_up_to_128, kp64.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial64 = cc->MultiAddEvalMultKeys(evalMultJoint63, evalMultJoint64, kp128.publicKey->GetKeyTag());
  auto evalMultJoint65 = cc->MultiMultEvalKey(evalMult_up_to_128, kp65.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial65 = cc->MultiAddEvalMultKeys(evalMultJoint64, evalMultJoint65, kp128.publicKey->GetKeyTag());
  auto evalMultJoint66 = cc->MultiMultEvalKey(evalMult_up_to_128, kp66.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial66 = cc->MultiAddEvalMultKeys(evalMultJoint65, evalMultJoint66, kp128.publicKey->GetKeyTag());
  auto evalMultJoint67 = cc->MultiMultEvalKey(evalMult_up_to_128, kp67.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial67 = cc->MultiAddEvalMultKeys(evalMultJoint66, evalMultJoint67, kp128.publicKey->GetKeyTag());
  auto evalMultJoint68 = cc->MultiMultEvalKey(evalMult_up_to_128, kp68.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial68 = cc->MultiAddEvalMultKeys(evalMultJoint67, evalMultJoint68, kp128.publicKey->GetKeyTag());
  auto evalMultJoint69 = cc->MultiMultEvalKey(evalMult_up_to_128, kp69.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial69 = cc->MultiAddEvalMultKeys(evalMultJoint68, evalMultJoint69, kp128.publicKey->GetKeyTag());
  auto evalMultJoint70 = cc->MultiMultEvalKey(evalMult_up_to_128, kp70.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial70 = cc->MultiAddEvalMultKeys(evalMultJoint69, evalMultJoint70, kp128.publicKey->GetKeyTag());
  auto evalMultJoint71 = cc->MultiMultEvalKey(evalMult_up_to_128, kp71.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial71 = cc->MultiAddEvalMultKeys(evalMultJoint70, evalMultJoint71, kp128.publicKey->GetKeyTag());
  auto evalMultJoint72 = cc->MultiMultEvalKey(evalMult_up_to_128, kp72.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial72 = cc->MultiAddEvalMultKeys(evalMultJoint71, evalMultJoint72, kp128.publicKey->GetKeyTag());
  auto evalMultJoint73 = cc->MultiMultEvalKey(evalMult_up_to_128, kp73.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial73 = cc->MultiAddEvalMultKeys(evalMultJoint72, evalMultJoint73, kp128.publicKey->GetKeyTag());
  auto evalMultJoint74 = cc->MultiMultEvalKey(evalMult_up_to_128, kp74.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial74 = cc->MultiAddEvalMultKeys(evalMultJoint73, evalMultJoint74, kp128.publicKey->GetKeyTag());
  auto evalMultJoint75 = cc->MultiMultEvalKey(evalMult_up_to_128, kp75.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial75 = cc->MultiAddEvalMultKeys(evalMultJoint74, evalMultJoint75, kp128.publicKey->GetKeyTag());
  auto evalMultJoint76 = cc->MultiMultEvalKey(evalMult_up_to_128, kp76.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial76 = cc->MultiAddEvalMultKeys(evalMultJoint75, evalMultJoint76, kp128.publicKey->GetKeyTag());
  auto evalMultJoint77 = cc->MultiMultEvalKey(evalMult_up_to_128, kp77.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial77 = cc->MultiAddEvalMultKeys(evalMultJoint76, evalMultJoint77, kp128.publicKey->GetKeyTag());
  auto evalMultJoint78 = cc->MultiMultEvalKey(evalMult_up_to_128, kp78.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial78 = cc->MultiAddEvalMultKeys(evalMultJoint77, evalMultJoint78, kp128.publicKey->GetKeyTag());
  auto evalMultJoint79 = cc->MultiMultEvalKey(evalMult_up_to_128, kp79.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial79 = cc->MultiAddEvalMultKeys(evalMultJoint78, evalMultJoint79, kp128.publicKey->GetKeyTag());
  auto evalMultJoint80 = cc->MultiMultEvalKey(evalMult_up_to_128, kp80.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial80 = cc->MultiAddEvalMultKeys(evalMultJoint79, evalMultJoint80, kp128.publicKey->GetKeyTag());
  auto evalMultJoint81 = cc->MultiMultEvalKey(evalMult_up_to_128, kp81.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial81 = cc->MultiAddEvalMultKeys(evalMultJoint80, evalMultJoint81, kp128.publicKey->GetKeyTag());
  auto evalMultJoint82 = cc->MultiMultEvalKey(evalMult_up_to_128, kp82.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial82 = cc->MultiAddEvalMultKeys(evalMultJoint81, evalMultJoint82, kp128.publicKey->GetKeyTag());
  auto evalMultJoint83 = cc->MultiMultEvalKey(evalMult_up_to_128, kp83.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial83 = cc->MultiAddEvalMultKeys(evalMultJoint82, evalMultJoint83, kp128.publicKey->GetKeyTag());
  auto evalMultJoint84 = cc->MultiMultEvalKey(evalMult_up_to_128, kp84.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial84 = cc->MultiAddEvalMultKeys(evalMultJoint83, evalMultJoint84, kp128.publicKey->GetKeyTag());
  auto evalMultJoint85 = cc->MultiMultEvalKey(evalMult_up_to_128, kp85.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial85 = cc->MultiAddEvalMultKeys(evalMultJoint84, evalMultJoint85, kp128.publicKey->GetKeyTag());
  auto evalMultJoint86 = cc->MultiMultEvalKey(evalMult_up_to_128, kp86.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial86 = cc->MultiAddEvalMultKeys(evalMultJoint85, evalMultJoint86, kp128.publicKey->GetKeyTag());
  auto evalMultJoint87 = cc->MultiMultEvalKey(evalMult_up_to_128, kp87.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial87 = cc->MultiAddEvalMultKeys(evalMultJoint86, evalMultJoint87, kp128.publicKey->GetKeyTag());
  auto evalMultJoint88 = cc->MultiMultEvalKey(evalMult_up_to_128, kp88.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial88 = cc->MultiAddEvalMultKeys(evalMultJoint87, evalMultJoint88, kp128.publicKey->GetKeyTag());
  auto evalMultJoint89 = cc->MultiMultEvalKey(evalMult_up_to_128, kp89.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial89 = cc->MultiAddEvalMultKeys(evalMultJoint88, evalMultJoint89, kp128.publicKey->GetKeyTag());
  auto evalMultJoint90 = cc->MultiMultEvalKey(evalMult_up_to_128, kp90.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial90 = cc->MultiAddEvalMultKeys(evalMultJoint89, evalMultJoint90, kp128.publicKey->GetKeyTag());
  auto evalMultJoint91 = cc->MultiMultEvalKey(evalMult_up_to_128, kp91.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial91 = cc->MultiAddEvalMultKeys(evalMultJoint90, evalMultJoint91, kp128.publicKey->GetKeyTag());
  auto evalMultJoint92 = cc->MultiMultEvalKey(evalMult_up_to_128, kp92.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial92 = cc->MultiAddEvalMultKeys(evalMultJoint91, evalMultJoint92, kp128.publicKey->GetKeyTag());
  auto evalMultJoint93 = cc->MultiMultEvalKey(evalMult_up_to_128, kp93.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial93 = cc->MultiAddEvalMultKeys(evalMultJoint92, evalMultJoint93, kp128.publicKey->GetKeyTag());
  auto evalMultJoint94 = cc->MultiMultEvalKey(evalMult_up_to_128, kp94.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial94 = cc->MultiAddEvalMultKeys(evalMultJoint93, evalMultJoint94, kp128.publicKey->GetKeyTag());
  auto evalMultJoint95 = cc->MultiMultEvalKey(evalMult_up_to_128, kp95.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial95 = cc->MultiAddEvalMultKeys(evalMultJoint94, evalMultJoint95, kp128.publicKey->GetKeyTag());
  auto evalMultJoint96 = cc->MultiMultEvalKey(evalMult_up_to_128, kp96.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial96 = cc->MultiAddEvalMultKeys(evalMultJoint95, evalMultJoint96, kp128.publicKey->GetKeyTag());
  auto evalMultJoint97 = cc->MultiMultEvalKey(evalMult_up_to_128, kp97.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial97 = cc->MultiAddEvalMultKeys(evalMultJoint96, evalMultJoint97, kp128.publicKey->GetKeyTag());
  auto evalMultJoint98 = cc->MultiMultEvalKey(evalMult_up_to_128, kp98.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial98 = cc->MultiAddEvalMultKeys(evalMultJoint97, evalMultJoint98, kp128.publicKey->GetKeyTag());
  auto evalMultJoint99 = cc->MultiMultEvalKey(evalMult_up_to_128, kp99.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial99 = cc->MultiAddEvalMultKeys(evalMultJoint98, evalMultJoint99, kp128.publicKey->GetKeyTag());
  auto evalMultJoint100 = cc->MultiMultEvalKey(evalMult_up_to_128, kp100.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial100 = cc->MultiAddEvalMultKeys(evalMultJoint99, evalMultJoint100, kp128.publicKey->GetKeyTag());
  auto evalMultJoint101 = cc->MultiMultEvalKey(evalMult_up_to_128, kp101.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial101 = cc->MultiAddEvalMultKeys(evalMultJoint100, evalMultJoint101, kp128.publicKey->GetKeyTag());
  auto evalMultJoint102 = cc->MultiMultEvalKey(evalMult_up_to_128, kp102.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial102 = cc->MultiAddEvalMultKeys(evalMultJoint101, evalMultJoint102, kp128.publicKey->GetKeyTag());
  auto evalMultJoint103 = cc->MultiMultEvalKey(evalMult_up_to_128, kp103.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial103 = cc->MultiAddEvalMultKeys(evalMultJoint102, evalMultJoint103, kp128.publicKey->GetKeyTag());
  auto evalMultJoint104 = cc->MultiMultEvalKey(evalMult_up_to_128, kp104.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial104 = cc->MultiAddEvalMultKeys(evalMultJoint103, evalMultJoint104, kp128.publicKey->GetKeyTag());
  auto evalMultJoint105 = cc->MultiMultEvalKey(evalMult_up_to_128, kp105.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial105 = cc->MultiAddEvalMultKeys(evalMultJoint104, evalMultJoint105, kp128.publicKey->GetKeyTag());
  auto evalMultJoint106 = cc->MultiMultEvalKey(evalMult_up_to_128, kp106.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial106 = cc->MultiAddEvalMultKeys(evalMultJoint105, evalMultJoint106, kp128.publicKey->GetKeyTag());
  auto evalMultJoint107 = cc->MultiMultEvalKey(evalMult_up_to_128, kp107.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial107 = cc->MultiAddEvalMultKeys(evalMultJoint106, evalMultJoint107, kp128.publicKey->GetKeyTag());
  auto evalMultJoint108 = cc->MultiMultEvalKey(evalMult_up_to_128, kp108.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial108 = cc->MultiAddEvalMultKeys(evalMultJoint107, evalMultJoint108, kp128.publicKey->GetKeyTag());
  auto evalMultJoint109 = cc->MultiMultEvalKey(evalMult_up_to_128, kp109.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial109 = cc->MultiAddEvalMultKeys(evalMultJoint108, evalMultJoint109, kp128.publicKey->GetKeyTag());
  auto evalMultJoint110 = cc->MultiMultEvalKey(evalMult_up_to_128, kp110.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial110 = cc->MultiAddEvalMultKeys(evalMultJoint109, evalMultJoint110, kp128.publicKey->GetKeyTag());
  auto evalMultJoint111 = cc->MultiMultEvalKey(evalMult_up_to_128, kp111.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial111 = cc->MultiAddEvalMultKeys(evalMultJoint110, evalMultJoint111, kp128.publicKey->GetKeyTag());
  auto evalMultJoint112 = cc->MultiMultEvalKey(evalMult_up_to_128, kp112.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial112 = cc->MultiAddEvalMultKeys(evalMultJoint111, evalMultJoint112, kp128.publicKey->GetKeyTag());
  auto evalMultJoint113 = cc->MultiMultEvalKey(evalMult_up_to_128, kp113.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial113 = cc->MultiAddEvalMultKeys(evalMultJoint112, evalMultJoint113, kp128.publicKey->GetKeyTag());
  auto evalMultJoint114 = cc->MultiMultEvalKey(evalMult_up_to_128, kp114.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial114 = cc->MultiAddEvalMultKeys(evalMultJoint113, evalMultJoint114, kp128.publicKey->GetKeyTag());
  auto evalMultJoint115 = cc->MultiMultEvalKey(evalMult_up_to_128, kp115.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial115 = cc->MultiAddEvalMultKeys(evalMultJoint114, evalMultJoint115, kp128.publicKey->GetKeyTag());
  auto evalMultJoint116 = cc->MultiMultEvalKey(evalMult_up_to_128, kp116.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial116 = cc->MultiAddEvalMultKeys(evalMultJoint115, evalMultJoint116, kp128.publicKey->GetKeyTag());
  auto evalMultJoint117 = cc->MultiMultEvalKey(evalMult_up_to_128, kp117.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial117 = cc->MultiAddEvalMultKeys(evalMultJoint116, evalMultJoint117, kp128.publicKey->GetKeyTag());
  auto evalMultJoint118 = cc->MultiMultEvalKey(evalMult_up_to_128, kp118.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial118 = cc->MultiAddEvalMultKeys(evalMultJoint117, evalMultJoint118, kp128.publicKey->GetKeyTag());
  auto evalMultJoint119 = cc->MultiMultEvalKey(evalMult_up_to_128, kp119.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial119 = cc->MultiAddEvalMultKeys(evalMultJoint118, evalMultJoint119, kp128.publicKey->GetKeyTag());
  auto evalMultJoint120 = cc->MultiMultEvalKey(evalMult_up_to_128, kp120.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial120 = cc->MultiAddEvalMultKeys(evalMultJoint119, evalMultJoint120, kp128.publicKey->GetKeyTag());
  auto evalMultJoint121 = cc->MultiMultEvalKey(evalMult_up_to_128, kp121.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial121 = cc->MultiAddEvalMultKeys(evalMultJoint120, evalMultJoint121, kp128.publicKey->GetKeyTag());
  auto evalMultJoint122 = cc->MultiMultEvalKey(evalMult_up_to_128, kp122.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial122 = cc->MultiAddEvalMultKeys(evalMultJoint121, evalMultJoint122, kp128.publicKey->GetKeyTag());
  auto evalMultJoint123 = cc->MultiMultEvalKey(evalMult_up_to_128, kp123.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial123 = cc->MultiAddEvalMultKeys(evalMultJoint122, evalMultJoint123, kp128.publicKey->GetKeyTag());
  auto evalMultJoint124 = cc->MultiMultEvalKey(evalMult_up_to_128, kp124.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial124 = cc->MultiAddEvalMultKeys(evalMultJoint123, evalMultJoint124, kp128.publicKey->GetKeyTag());
  auto evalMultJoint125 = cc->MultiMultEvalKey(evalMult_up_to_128, kp125.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial125 = cc->MultiAddEvalMultKeys(evalMultJoint124, evalMultJoint125, kp128.publicKey->GetKeyTag());
  auto evalMultJoint126 = cc->MultiMultEvalKey(evalMult_up_to_128, kp126.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial126 = cc->MultiAddEvalMultKeys(evalMultJoint125, evalMultJoint126, kp128.publicKey->GetKeyTag());
  auto evalMultJoint127 = cc->MultiMultEvalKey(evalMult_up_to_128, kp127.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial127 = cc->MultiAddEvalMultKeys(evalMultJoint126, evalMultJoint127, kp128.publicKey->GetKeyTag());
  auto evalMultJoint128 = cc->MultiMultEvalKey(evalMult_up_to_128, kp128.secretKey, kp128.publicKey->GetKeyTag());
  auto evalMultPartial128 = cc->MultiAddEvalMultKeys(evalMultJoint127, evalMultJoint128, kp128.publicKey->GetKeyTag());

  // insert final mult key
  cc->InsertEvalMultKey({evalMultPartial128});

  // insert final sum key 
  cc->InsertEvalSumKey(evalSumKeysJoin_to_128);
  std::cout << "Keys generated!" << std::endl;

  Plaintext plaintext0 = cc->MakePackedPlaintext(sketch_buckets[0]);
  Ciphertext<DCRTPoly> cipher_mult0_0;
  cipher_mult0_0 = cc->Encrypt(kp127.publicKey, plaintext0);

  Plaintext plaintext1 = cc->MakePackedPlaintext(sketch_buckets[1]);
  Ciphertext<DCRTPoly> cipher_mult0_1;
  cipher_mult0_1 = cc->Encrypt(kp127.publicKey, plaintext1);

  Plaintext plaintext2 = cc->MakePackedPlaintext(sketch_buckets[2]);
  Ciphertext<DCRTPoly> cipher_mult0_2;
  cipher_mult0_2 = cc->Encrypt(kp127.publicKey, plaintext2);

  Plaintext plaintext3 = cc->MakePackedPlaintext(sketch_buckets[3]);
  Ciphertext<DCRTPoly> cipher_mult0_3;
  cipher_mult0_3 = cc->Encrypt(kp127.publicKey, plaintext3);

  Plaintext plaintext4 = cc->MakePackedPlaintext(sketch_buckets[4]);
  Ciphertext<DCRTPoly> cipher_mult0_4;
  cipher_mult0_4 = cc->Encrypt(kp127.publicKey, plaintext4);

  Plaintext plaintext5 = cc->MakePackedPlaintext(sketch_buckets[5]);
  Ciphertext<DCRTPoly> cipher_mult0_5;
  cipher_mult0_5 = cc->Encrypt(kp127.publicKey, plaintext5);

  Plaintext plaintext6 = cc->MakePackedPlaintext(sketch_buckets[6]);
  Ciphertext<DCRTPoly> cipher_mult0_6;
  cipher_mult0_6 = cc->Encrypt(kp127.publicKey, plaintext6);

  Plaintext plaintext7 = cc->MakePackedPlaintext(sketch_buckets[7]);
  Ciphertext<DCRTPoly> cipher_mult0_7;
  cipher_mult0_7 = cc->Encrypt(kp127.publicKey, plaintext7);

  Plaintext plaintext8 = cc->MakePackedPlaintext(sketch_buckets[8]);
  Ciphertext<DCRTPoly> cipher_mult0_8;
  cipher_mult0_8 = cc->Encrypt(kp127.publicKey, plaintext8);

  Plaintext plaintext9 = cc->MakePackedPlaintext(sketch_buckets[9]);
  Ciphertext<DCRTPoly> cipher_mult0_9;
  cipher_mult0_9 = cc->Encrypt(kp127.publicKey, plaintext9);

  Plaintext plaintext10 = cc->MakePackedPlaintext(sketch_buckets[10]);
  Ciphertext<DCRTPoly> cipher_mult0_10;
  cipher_mult0_10 = cc->Encrypt(kp127.publicKey, plaintext10);

  Plaintext plaintext11 = cc->MakePackedPlaintext(sketch_buckets[11]);
  Ciphertext<DCRTPoly> cipher_mult0_11;
  cipher_mult0_11 = cc->Encrypt(kp127.publicKey, plaintext11);

  Plaintext plaintext12 = cc->MakePackedPlaintext(sketch_buckets[12]);
  Ciphertext<DCRTPoly> cipher_mult0_12;
  cipher_mult0_12 = cc->Encrypt(kp127.publicKey, plaintext12);

  Plaintext plaintext13 = cc->MakePackedPlaintext(sketch_buckets[13]);
  Ciphertext<DCRTPoly> cipher_mult0_13;
  cipher_mult0_13 = cc->Encrypt(kp127.publicKey, plaintext13);

  Plaintext plaintext14 = cc->MakePackedPlaintext(sketch_buckets[14]);
  Ciphertext<DCRTPoly> cipher_mult0_14;
  cipher_mult0_14 = cc->Encrypt(kp127.publicKey, plaintext14);

  Plaintext plaintext15 = cc->MakePackedPlaintext(sketch_buckets[15]);
  Ciphertext<DCRTPoly> cipher_mult0_15;
  cipher_mult0_15 = cc->Encrypt(kp127.publicKey, plaintext15);

  Plaintext plaintext16 = cc->MakePackedPlaintext(sketch_buckets[16]);
  Ciphertext<DCRTPoly> cipher_mult0_16;
  cipher_mult0_16 = cc->Encrypt(kp127.publicKey, plaintext16);

  Plaintext plaintext17 = cc->MakePackedPlaintext(sketch_buckets[17]);
  Ciphertext<DCRTPoly> cipher_mult0_17;
  cipher_mult0_17 = cc->Encrypt(kp127.publicKey, plaintext17);

  Plaintext plaintext18 = cc->MakePackedPlaintext(sketch_buckets[18]);
  Ciphertext<DCRTPoly> cipher_mult0_18;
  cipher_mult0_18 = cc->Encrypt(kp127.publicKey, plaintext18);

  Plaintext plaintext19 = cc->MakePackedPlaintext(sketch_buckets[19]);
  Ciphertext<DCRTPoly> cipher_mult0_19;
  cipher_mult0_19 = cc->Encrypt(kp127.publicKey, plaintext19);

  Plaintext plaintext20 = cc->MakePackedPlaintext(sketch_buckets[20]);
  Ciphertext<DCRTPoly> cipher_mult0_20;
  cipher_mult0_20 = cc->Encrypt(kp127.publicKey, plaintext20);

  Plaintext plaintext21 = cc->MakePackedPlaintext(sketch_buckets[21]);
  Ciphertext<DCRTPoly> cipher_mult0_21;
  cipher_mult0_21 = cc->Encrypt(kp127.publicKey, plaintext21);

  Plaintext plaintext22 = cc->MakePackedPlaintext(sketch_buckets[22]);
  Ciphertext<DCRTPoly> cipher_mult0_22;
  cipher_mult0_22 = cc->Encrypt(kp127.publicKey, plaintext22);

  Plaintext plaintext23 = cc->MakePackedPlaintext(sketch_buckets[23]);
  Ciphertext<DCRTPoly> cipher_mult0_23;
  cipher_mult0_23 = cc->Encrypt(kp127.publicKey, plaintext23);

  Plaintext plaintext24 = cc->MakePackedPlaintext(sketch_buckets[24]);
  Ciphertext<DCRTPoly> cipher_mult0_24;
  cipher_mult0_24 = cc->Encrypt(kp127.publicKey, plaintext24);

  Plaintext plaintext25 = cc->MakePackedPlaintext(sketch_buckets[25]);
  Ciphertext<DCRTPoly> cipher_mult0_25;
  cipher_mult0_25 = cc->Encrypt(kp127.publicKey, plaintext25);

  Plaintext plaintext26 = cc->MakePackedPlaintext(sketch_buckets[26]);
  Ciphertext<DCRTPoly> cipher_mult0_26;
  cipher_mult0_26 = cc->Encrypt(kp127.publicKey, plaintext26);

  Plaintext plaintext27 = cc->MakePackedPlaintext(sketch_buckets[27]);
  Ciphertext<DCRTPoly> cipher_mult0_27;
  cipher_mult0_27 = cc->Encrypt(kp127.publicKey, plaintext27);

  Plaintext plaintext28 = cc->MakePackedPlaintext(sketch_buckets[28]);
  Ciphertext<DCRTPoly> cipher_mult0_28;
  cipher_mult0_28 = cc->Encrypt(kp127.publicKey, plaintext28);

  Plaintext plaintext29 = cc->MakePackedPlaintext(sketch_buckets[29]);
  Ciphertext<DCRTPoly> cipher_mult0_29;
  cipher_mult0_29 = cc->Encrypt(kp127.publicKey, plaintext29);

  Plaintext plaintext30 = cc->MakePackedPlaintext(sketch_buckets[30]);
  Ciphertext<DCRTPoly> cipher_mult0_30;
  cipher_mult0_30 = cc->Encrypt(kp127.publicKey, plaintext30);

  Plaintext plaintext31 = cc->MakePackedPlaintext(sketch_buckets[31]);
  Ciphertext<DCRTPoly> cipher_mult0_31;
  cipher_mult0_31 = cc->Encrypt(kp127.publicKey, plaintext31);

  Plaintext plaintext32 = cc->MakePackedPlaintext(sketch_buckets[32]);
  Ciphertext<DCRTPoly> cipher_mult0_32;
  cipher_mult0_32 = cc->Encrypt(kp127.publicKey, plaintext32);

  Plaintext plaintext33 = cc->MakePackedPlaintext(sketch_buckets[33]);
  Ciphertext<DCRTPoly> cipher_mult0_33;
  cipher_mult0_33 = cc->Encrypt(kp127.publicKey, plaintext33);

  Plaintext plaintext34 = cc->MakePackedPlaintext(sketch_buckets[34]);
  Ciphertext<DCRTPoly> cipher_mult0_34;
  cipher_mult0_34 = cc->Encrypt(kp127.publicKey, plaintext34);

  Plaintext plaintext35 = cc->MakePackedPlaintext(sketch_buckets[35]);
  Ciphertext<DCRTPoly> cipher_mult0_35;
  cipher_mult0_35 = cc->Encrypt(kp127.publicKey, plaintext35);

  Plaintext plaintext36 = cc->MakePackedPlaintext(sketch_buckets[36]);
  Ciphertext<DCRTPoly> cipher_mult0_36;
  cipher_mult0_36 = cc->Encrypt(kp127.publicKey, plaintext36);

  Plaintext plaintext37 = cc->MakePackedPlaintext(sketch_buckets[37]);
  Ciphertext<DCRTPoly> cipher_mult0_37;
  cipher_mult0_37 = cc->Encrypt(kp127.publicKey, plaintext37);

  Plaintext plaintext38 = cc->MakePackedPlaintext(sketch_buckets[38]);
  Ciphertext<DCRTPoly> cipher_mult0_38;
  cipher_mult0_38 = cc->Encrypt(kp127.publicKey, plaintext38);

  Plaintext plaintext39 = cc->MakePackedPlaintext(sketch_buckets[39]);
  Ciphertext<DCRTPoly> cipher_mult0_39;
  cipher_mult0_39 = cc->Encrypt(kp127.publicKey, plaintext39);

  Plaintext plaintext40 = cc->MakePackedPlaintext(sketch_buckets[40]);
  Ciphertext<DCRTPoly> cipher_mult0_40;
  cipher_mult0_40 = cc->Encrypt(kp127.publicKey, plaintext40);

  Plaintext plaintext41 = cc->MakePackedPlaintext(sketch_buckets[41]);
  Ciphertext<DCRTPoly> cipher_mult0_41;
  cipher_mult0_41 = cc->Encrypt(kp127.publicKey, plaintext41);

  Plaintext plaintext42 = cc->MakePackedPlaintext(sketch_buckets[42]);
  Ciphertext<DCRTPoly> cipher_mult0_42;
  cipher_mult0_42 = cc->Encrypt(kp127.publicKey, plaintext42);

  Plaintext plaintext43 = cc->MakePackedPlaintext(sketch_buckets[43]);
  Ciphertext<DCRTPoly> cipher_mult0_43;
  cipher_mult0_43 = cc->Encrypt(kp127.publicKey, plaintext43);

  Plaintext plaintext44 = cc->MakePackedPlaintext(sketch_buckets[44]);
  Ciphertext<DCRTPoly> cipher_mult0_44;
  cipher_mult0_44 = cc->Encrypt(kp127.publicKey, plaintext44);

  Plaintext plaintext45 = cc->MakePackedPlaintext(sketch_buckets[45]);
  Ciphertext<DCRTPoly> cipher_mult0_45;
  cipher_mult0_45 = cc->Encrypt(kp127.publicKey, plaintext45);

  Plaintext plaintext46 = cc->MakePackedPlaintext(sketch_buckets[46]);
  Ciphertext<DCRTPoly> cipher_mult0_46;
  cipher_mult0_46 = cc->Encrypt(kp127.publicKey, plaintext46);

  Plaintext plaintext47 = cc->MakePackedPlaintext(sketch_buckets[47]);
  Ciphertext<DCRTPoly> cipher_mult0_47;
  cipher_mult0_47 = cc->Encrypt(kp127.publicKey, plaintext47);

  Plaintext plaintext48 = cc->MakePackedPlaintext(sketch_buckets[48]);
  Ciphertext<DCRTPoly> cipher_mult0_48;
  cipher_mult0_48 = cc->Encrypt(kp127.publicKey, plaintext48);

  Plaintext plaintext49 = cc->MakePackedPlaintext(sketch_buckets[49]);
  Ciphertext<DCRTPoly> cipher_mult0_49;
  cipher_mult0_49 = cc->Encrypt(kp127.publicKey, plaintext49);

  Plaintext plaintext50 = cc->MakePackedPlaintext(sketch_buckets[50]);
  Ciphertext<DCRTPoly> cipher_mult0_50;
  cipher_mult0_50 = cc->Encrypt(kp127.publicKey, plaintext50);

  Plaintext plaintext51 = cc->MakePackedPlaintext(sketch_buckets[51]);
  Ciphertext<DCRTPoly> cipher_mult0_51;
  cipher_mult0_51 = cc->Encrypt(kp127.publicKey, plaintext51);

  Plaintext plaintext52 = cc->MakePackedPlaintext(sketch_buckets[52]);
  Ciphertext<DCRTPoly> cipher_mult0_52;
  cipher_mult0_52 = cc->Encrypt(kp127.publicKey, plaintext52);

  Plaintext plaintext53 = cc->MakePackedPlaintext(sketch_buckets[53]);
  Ciphertext<DCRTPoly> cipher_mult0_53;
  cipher_mult0_53 = cc->Encrypt(kp127.publicKey, plaintext53);

  Plaintext plaintext54 = cc->MakePackedPlaintext(sketch_buckets[54]);
  Ciphertext<DCRTPoly> cipher_mult0_54;
  cipher_mult0_54 = cc->Encrypt(kp127.publicKey, plaintext54);

  Plaintext plaintext55 = cc->MakePackedPlaintext(sketch_buckets[55]);
  Ciphertext<DCRTPoly> cipher_mult0_55;
  cipher_mult0_55 = cc->Encrypt(kp127.publicKey, plaintext55);

  Plaintext plaintext56 = cc->MakePackedPlaintext(sketch_buckets[56]);
  Ciphertext<DCRTPoly> cipher_mult0_56;
  cipher_mult0_56 = cc->Encrypt(kp127.publicKey, plaintext56);

  Plaintext plaintext57 = cc->MakePackedPlaintext(sketch_buckets[57]);
  Ciphertext<DCRTPoly> cipher_mult0_57;
  cipher_mult0_57 = cc->Encrypt(kp127.publicKey, plaintext57);

  Plaintext plaintext58 = cc->MakePackedPlaintext(sketch_buckets[58]);
  Ciphertext<DCRTPoly> cipher_mult0_58;
  cipher_mult0_58 = cc->Encrypt(kp127.publicKey, plaintext58);

  Plaintext plaintext59 = cc->MakePackedPlaintext(sketch_buckets[59]);
  Ciphertext<DCRTPoly> cipher_mult0_59;
  cipher_mult0_59 = cc->Encrypt(kp127.publicKey, plaintext59);

  Plaintext plaintext60 = cc->MakePackedPlaintext(sketch_buckets[60]);
  Ciphertext<DCRTPoly> cipher_mult0_60;
  cipher_mult0_60 = cc->Encrypt(kp127.publicKey, plaintext60);

  Plaintext plaintext61 = cc->MakePackedPlaintext(sketch_buckets[61]);
  Ciphertext<DCRTPoly> cipher_mult0_61;
  cipher_mult0_61 = cc->Encrypt(kp127.publicKey, plaintext61);

  Plaintext plaintext62 = cc->MakePackedPlaintext(sketch_buckets[62]);
  Ciphertext<DCRTPoly> cipher_mult0_62;
  cipher_mult0_62 = cc->Encrypt(kp127.publicKey, plaintext62);

  Plaintext plaintext63 = cc->MakePackedPlaintext(sketch_buckets[63]);
  Ciphertext<DCRTPoly> cipher_mult0_63;
  cipher_mult0_63 = cc->Encrypt(kp127.publicKey, plaintext63);

  Plaintext plaintext64 = cc->MakePackedPlaintext(sketch_buckets[64]);
  Ciphertext<DCRTPoly> cipher_mult0_64;
  cipher_mult0_64 = cc->Encrypt(kp127.publicKey, plaintext64);

  Plaintext plaintext65 = cc->MakePackedPlaintext(sketch_buckets[65]);
  Ciphertext<DCRTPoly> cipher_mult0_65;
  cipher_mult0_65 = cc->Encrypt(kp127.publicKey, plaintext65);

  Plaintext plaintext66 = cc->MakePackedPlaintext(sketch_buckets[66]);
  Ciphertext<DCRTPoly> cipher_mult0_66;
  cipher_mult0_66 = cc->Encrypt(kp127.publicKey, plaintext66);

  Plaintext plaintext67 = cc->MakePackedPlaintext(sketch_buckets[67]);
  Ciphertext<DCRTPoly> cipher_mult0_67;
  cipher_mult0_67 = cc->Encrypt(kp127.publicKey, plaintext67);

  Plaintext plaintext68 = cc->MakePackedPlaintext(sketch_buckets[68]);
  Ciphertext<DCRTPoly> cipher_mult0_68;
  cipher_mult0_68 = cc->Encrypt(kp127.publicKey, plaintext68);

  Plaintext plaintext69 = cc->MakePackedPlaintext(sketch_buckets[69]);
  Ciphertext<DCRTPoly> cipher_mult0_69;
  cipher_mult0_69 = cc->Encrypt(kp127.publicKey, plaintext69);

  Plaintext plaintext70 = cc->MakePackedPlaintext(sketch_buckets[70]);
  Ciphertext<DCRTPoly> cipher_mult0_70;
  cipher_mult0_70 = cc->Encrypt(kp127.publicKey, plaintext70);

  Plaintext plaintext71 = cc->MakePackedPlaintext(sketch_buckets[71]);
  Ciphertext<DCRTPoly> cipher_mult0_71;
  cipher_mult0_71 = cc->Encrypt(kp127.publicKey, plaintext71);

  Plaintext plaintext72 = cc->MakePackedPlaintext(sketch_buckets[72]);
  Ciphertext<DCRTPoly> cipher_mult0_72;
  cipher_mult0_72 = cc->Encrypt(kp127.publicKey, plaintext72);

  Plaintext plaintext73 = cc->MakePackedPlaintext(sketch_buckets[73]);
  Ciphertext<DCRTPoly> cipher_mult0_73;
  cipher_mult0_73 = cc->Encrypt(kp127.publicKey, plaintext73);

  Plaintext plaintext74 = cc->MakePackedPlaintext(sketch_buckets[74]);
  Ciphertext<DCRTPoly> cipher_mult0_74;
  cipher_mult0_74 = cc->Encrypt(kp127.publicKey, plaintext74);

  Plaintext plaintext75 = cc->MakePackedPlaintext(sketch_buckets[75]);
  Ciphertext<DCRTPoly> cipher_mult0_75;
  cipher_mult0_75 = cc->Encrypt(kp127.publicKey, plaintext75);

  Plaintext plaintext76 = cc->MakePackedPlaintext(sketch_buckets[76]);
  Ciphertext<DCRTPoly> cipher_mult0_76;
  cipher_mult0_76 = cc->Encrypt(kp127.publicKey, plaintext76);

  Plaintext plaintext77 = cc->MakePackedPlaintext(sketch_buckets[77]);
  Ciphertext<DCRTPoly> cipher_mult0_77;
  cipher_mult0_77 = cc->Encrypt(kp127.publicKey, plaintext77);

  Plaintext plaintext78 = cc->MakePackedPlaintext(sketch_buckets[78]);
  Ciphertext<DCRTPoly> cipher_mult0_78;
  cipher_mult0_78 = cc->Encrypt(kp127.publicKey, plaintext78);

  Plaintext plaintext79 = cc->MakePackedPlaintext(sketch_buckets[79]);
  Ciphertext<DCRTPoly> cipher_mult0_79;
  cipher_mult0_79 = cc->Encrypt(kp127.publicKey, plaintext79);

  Plaintext plaintext80 = cc->MakePackedPlaintext(sketch_buckets[80]);
  Ciphertext<DCRTPoly> cipher_mult0_80;
  cipher_mult0_80 = cc->Encrypt(kp127.publicKey, plaintext80);

  Plaintext plaintext81 = cc->MakePackedPlaintext(sketch_buckets[81]);
  Ciphertext<DCRTPoly> cipher_mult0_81;
  cipher_mult0_81 = cc->Encrypt(kp127.publicKey, plaintext81);

  Plaintext plaintext82 = cc->MakePackedPlaintext(sketch_buckets[82]);
  Ciphertext<DCRTPoly> cipher_mult0_82;
  cipher_mult0_82 = cc->Encrypt(kp127.publicKey, plaintext82);

  Plaintext plaintext83 = cc->MakePackedPlaintext(sketch_buckets[83]);
  Ciphertext<DCRTPoly> cipher_mult0_83;
  cipher_mult0_83 = cc->Encrypt(kp127.publicKey, plaintext83);

  Plaintext plaintext84 = cc->MakePackedPlaintext(sketch_buckets[84]);
  Ciphertext<DCRTPoly> cipher_mult0_84;
  cipher_mult0_84 = cc->Encrypt(kp127.publicKey, plaintext84);

  Plaintext plaintext85 = cc->MakePackedPlaintext(sketch_buckets[85]);
  Ciphertext<DCRTPoly> cipher_mult0_85;
  cipher_mult0_85 = cc->Encrypt(kp127.publicKey, plaintext85);

  Plaintext plaintext86 = cc->MakePackedPlaintext(sketch_buckets[86]);
  Ciphertext<DCRTPoly> cipher_mult0_86;
  cipher_mult0_86 = cc->Encrypt(kp127.publicKey, plaintext86);

  Plaintext plaintext87 = cc->MakePackedPlaintext(sketch_buckets[87]);
  Ciphertext<DCRTPoly> cipher_mult0_87;
  cipher_mult0_87 = cc->Encrypt(kp127.publicKey, plaintext87);

  Plaintext plaintext88 = cc->MakePackedPlaintext(sketch_buckets[88]);
  Ciphertext<DCRTPoly> cipher_mult0_88;
  cipher_mult0_88 = cc->Encrypt(kp127.publicKey, plaintext88);

  Plaintext plaintext89 = cc->MakePackedPlaintext(sketch_buckets[89]);
  Ciphertext<DCRTPoly> cipher_mult0_89;
  cipher_mult0_89 = cc->Encrypt(kp127.publicKey, plaintext89);

  Plaintext plaintext90 = cc->MakePackedPlaintext(sketch_buckets[90]);
  Ciphertext<DCRTPoly> cipher_mult0_90;
  cipher_mult0_90 = cc->Encrypt(kp127.publicKey, plaintext90);

  Plaintext plaintext91 = cc->MakePackedPlaintext(sketch_buckets[91]);
  Ciphertext<DCRTPoly> cipher_mult0_91;
  cipher_mult0_91 = cc->Encrypt(kp127.publicKey, plaintext91);

  Plaintext plaintext92 = cc->MakePackedPlaintext(sketch_buckets[92]);
  Ciphertext<DCRTPoly> cipher_mult0_92;
  cipher_mult0_92 = cc->Encrypt(kp127.publicKey, plaintext92);

  Plaintext plaintext93 = cc->MakePackedPlaintext(sketch_buckets[93]);
  Ciphertext<DCRTPoly> cipher_mult0_93;
  cipher_mult0_93 = cc->Encrypt(kp127.publicKey, plaintext93);

  Plaintext plaintext94 = cc->MakePackedPlaintext(sketch_buckets[94]);
  Ciphertext<DCRTPoly> cipher_mult0_94;
  cipher_mult0_94 = cc->Encrypt(kp127.publicKey, plaintext94);

  Plaintext plaintext95 = cc->MakePackedPlaintext(sketch_buckets[95]);
  Ciphertext<DCRTPoly> cipher_mult0_95;
  cipher_mult0_95 = cc->Encrypt(kp127.publicKey, plaintext95);

  Plaintext plaintext96 = cc->MakePackedPlaintext(sketch_buckets[96]);
  Ciphertext<DCRTPoly> cipher_mult0_96;
  cipher_mult0_96 = cc->Encrypt(kp127.publicKey, plaintext96);

  Plaintext plaintext97 = cc->MakePackedPlaintext(sketch_buckets[97]);
  Ciphertext<DCRTPoly> cipher_mult0_97;
  cipher_mult0_97 = cc->Encrypt(kp127.publicKey, plaintext97);

  Plaintext plaintext98 = cc->MakePackedPlaintext(sketch_buckets[98]);
  Ciphertext<DCRTPoly> cipher_mult0_98;
  cipher_mult0_98 = cc->Encrypt(kp127.publicKey, plaintext98);

  Plaintext plaintext99 = cc->MakePackedPlaintext(sketch_buckets[99]);
  Ciphertext<DCRTPoly> cipher_mult0_99;
  cipher_mult0_99 = cc->Encrypt(kp127.publicKey, plaintext99);

  Plaintext plaintext100 = cc->MakePackedPlaintext(sketch_buckets[100]);
  Ciphertext<DCRTPoly> cipher_mult0_100;
  cipher_mult0_100 = cc->Encrypt(kp127.publicKey, plaintext100);

  Plaintext plaintext101 = cc->MakePackedPlaintext(sketch_buckets[101]);
  Ciphertext<DCRTPoly> cipher_mult0_101;
  cipher_mult0_101 = cc->Encrypt(kp127.publicKey, plaintext101);

  Plaintext plaintext102 = cc->MakePackedPlaintext(sketch_buckets[102]);
  Ciphertext<DCRTPoly> cipher_mult0_102;
  cipher_mult0_102 = cc->Encrypt(kp127.publicKey, plaintext102);

  Plaintext plaintext103 = cc->MakePackedPlaintext(sketch_buckets[103]);
  Ciphertext<DCRTPoly> cipher_mult0_103;
  cipher_mult0_103 = cc->Encrypt(kp127.publicKey, plaintext103);

  Plaintext plaintext104 = cc->MakePackedPlaintext(sketch_buckets[104]);
  Ciphertext<DCRTPoly> cipher_mult0_104;
  cipher_mult0_104 = cc->Encrypt(kp127.publicKey, plaintext104);

  Plaintext plaintext105 = cc->MakePackedPlaintext(sketch_buckets[105]);
  Ciphertext<DCRTPoly> cipher_mult0_105;
  cipher_mult0_105 = cc->Encrypt(kp127.publicKey, plaintext105);

  Plaintext plaintext106 = cc->MakePackedPlaintext(sketch_buckets[106]);
  Ciphertext<DCRTPoly> cipher_mult0_106;
  cipher_mult0_106 = cc->Encrypt(kp127.publicKey, plaintext106);

  Plaintext plaintext107 = cc->MakePackedPlaintext(sketch_buckets[107]);
  Ciphertext<DCRTPoly> cipher_mult0_107;
  cipher_mult0_107 = cc->Encrypt(kp127.publicKey, plaintext107);

  Plaintext plaintext108 = cc->MakePackedPlaintext(sketch_buckets[108]);
  Ciphertext<DCRTPoly> cipher_mult0_108;
  cipher_mult0_108 = cc->Encrypt(kp127.publicKey, plaintext108);

  Plaintext plaintext109 = cc->MakePackedPlaintext(sketch_buckets[109]);
  Ciphertext<DCRTPoly> cipher_mult0_109;
  cipher_mult0_109 = cc->Encrypt(kp127.publicKey, plaintext109);

  Plaintext plaintext110 = cc->MakePackedPlaintext(sketch_buckets[110]);
  Ciphertext<DCRTPoly> cipher_mult0_110;
  cipher_mult0_110 = cc->Encrypt(kp127.publicKey, plaintext110);

  Plaintext plaintext111 = cc->MakePackedPlaintext(sketch_buckets[111]);
  Ciphertext<DCRTPoly> cipher_mult0_111;
  cipher_mult0_111 = cc->Encrypt(kp127.publicKey, plaintext111);

  Plaintext plaintext112 = cc->MakePackedPlaintext(sketch_buckets[112]);
  Ciphertext<DCRTPoly> cipher_mult0_112;
  cipher_mult0_112 = cc->Encrypt(kp127.publicKey, plaintext112);

  Plaintext plaintext113 = cc->MakePackedPlaintext(sketch_buckets[113]);
  Ciphertext<DCRTPoly> cipher_mult0_113;
  cipher_mult0_113 = cc->Encrypt(kp127.publicKey, plaintext113);

  Plaintext plaintext114 = cc->MakePackedPlaintext(sketch_buckets[114]);
  Ciphertext<DCRTPoly> cipher_mult0_114;
  cipher_mult0_114 = cc->Encrypt(kp127.publicKey, plaintext114);

  Plaintext plaintext115 = cc->MakePackedPlaintext(sketch_buckets[115]);
  Ciphertext<DCRTPoly> cipher_mult0_115;
  cipher_mult0_115 = cc->Encrypt(kp127.publicKey, plaintext115);

  Plaintext plaintext116 = cc->MakePackedPlaintext(sketch_buckets[116]);
  Ciphertext<DCRTPoly> cipher_mult0_116;
  cipher_mult0_116 = cc->Encrypt(kp127.publicKey, plaintext116);

  Plaintext plaintext117 = cc->MakePackedPlaintext(sketch_buckets[117]);
  Ciphertext<DCRTPoly> cipher_mult0_117;
  cipher_mult0_117 = cc->Encrypt(kp127.publicKey, plaintext117);

  Plaintext plaintext118 = cc->MakePackedPlaintext(sketch_buckets[118]);
  Ciphertext<DCRTPoly> cipher_mult0_118;
  cipher_mult0_118 = cc->Encrypt(kp127.publicKey, plaintext118);

  Plaintext plaintext119 = cc->MakePackedPlaintext(sketch_buckets[119]);
  Ciphertext<DCRTPoly> cipher_mult0_119;
  cipher_mult0_119 = cc->Encrypt(kp127.publicKey, plaintext119);

  Plaintext plaintext120 = cc->MakePackedPlaintext(sketch_buckets[120]);
  Ciphertext<DCRTPoly> cipher_mult0_120;
  cipher_mult0_120 = cc->Encrypt(kp127.publicKey, plaintext120);

  Plaintext plaintext121 = cc->MakePackedPlaintext(sketch_buckets[121]);
  Ciphertext<DCRTPoly> cipher_mult0_121;
  cipher_mult0_121 = cc->Encrypt(kp127.publicKey, plaintext121);

  Plaintext plaintext122 = cc->MakePackedPlaintext(sketch_buckets[122]);
  Ciphertext<DCRTPoly> cipher_mult0_122;
  cipher_mult0_122 = cc->Encrypt(kp127.publicKey, plaintext122);

  Plaintext plaintext123 = cc->MakePackedPlaintext(sketch_buckets[123]);
  Ciphertext<DCRTPoly> cipher_mult0_123;
  cipher_mult0_123 = cc->Encrypt(kp127.publicKey, plaintext123);

  Plaintext plaintext124 = cc->MakePackedPlaintext(sketch_buckets[124]);
  Ciphertext<DCRTPoly> cipher_mult0_124;
  cipher_mult0_124 = cc->Encrypt(kp127.publicKey, plaintext124);

  Plaintext plaintext125 = cc->MakePackedPlaintext(sketch_buckets[125]);
  Ciphertext<DCRTPoly> cipher_mult0_125;
  cipher_mult0_125 = cc->Encrypt(kp127.publicKey, plaintext125);

  Plaintext plaintext126 = cc->MakePackedPlaintext(sketch_buckets[126]);
  Ciphertext<DCRTPoly> cipher_mult0_126;
  cipher_mult0_126 = cc->Encrypt(kp127.publicKey, plaintext126);

  Plaintext plaintext127 = cc->MakePackedPlaintext(sketch_buckets[127]);
  Ciphertext<DCRTPoly> cipher_mult0_127;
  cipher_mult0_127 = cc->Encrypt(kp127.publicKey, plaintext127);

  // Tree mult - final product stored in cipher_mult0
  auto cipher_mult1_0 = cc->EvalMult(cipher_mult0_0, cipher_mult0_64);
  auto cipher_mult1_1 = cc->EvalMult(cipher_mult0_1, cipher_mult0_65);
  auto cipher_mult1_2 = cc->EvalMult(cipher_mult0_2, cipher_mult0_66);
  auto cipher_mult1_3 = cc->EvalMult(cipher_mult0_3, cipher_mult0_67);
  auto cipher_mult1_4 = cc->EvalMult(cipher_mult0_4, cipher_mult0_68);
  auto cipher_mult1_5 = cc->EvalMult(cipher_mult0_5, cipher_mult0_69);
  auto cipher_mult1_6 = cc->EvalMult(cipher_mult0_6, cipher_mult0_70);
  auto cipher_mult1_7 = cc->EvalMult(cipher_mult0_7, cipher_mult0_71);
  auto cipher_mult1_8 = cc->EvalMult(cipher_mult0_8, cipher_mult0_72);
  auto cipher_mult1_9 = cc->EvalMult(cipher_mult0_9, cipher_mult0_73);
  auto cipher_mult1_10 = cc->EvalMult(cipher_mult0_10, cipher_mult0_74);
  auto cipher_mult1_11 = cc->EvalMult(cipher_mult0_11, cipher_mult0_75);
  auto cipher_mult1_12 = cc->EvalMult(cipher_mult0_12, cipher_mult0_76);
  auto cipher_mult1_13 = cc->EvalMult(cipher_mult0_13, cipher_mult0_77);
  auto cipher_mult1_14 = cc->EvalMult(cipher_mult0_14, cipher_mult0_78);
  auto cipher_mult1_15 = cc->EvalMult(cipher_mult0_15, cipher_mult0_79);
  auto cipher_mult1_16 = cc->EvalMult(cipher_mult0_16, cipher_mult0_80);
  auto cipher_mult1_17 = cc->EvalMult(cipher_mult0_17, cipher_mult0_81);
  auto cipher_mult1_18 = cc->EvalMult(cipher_mult0_18, cipher_mult0_82);
  auto cipher_mult1_19 = cc->EvalMult(cipher_mult0_19, cipher_mult0_83);
  auto cipher_mult1_20 = cc->EvalMult(cipher_mult0_20, cipher_mult0_84);
  auto cipher_mult1_21 = cc->EvalMult(cipher_mult0_21, cipher_mult0_85);
  auto cipher_mult1_22 = cc->EvalMult(cipher_mult0_22, cipher_mult0_86);
  auto cipher_mult1_23 = cc->EvalMult(cipher_mult0_23, cipher_mult0_87);
  auto cipher_mult1_24 = cc->EvalMult(cipher_mult0_24, cipher_mult0_88);
  auto cipher_mult1_25 = cc->EvalMult(cipher_mult0_25, cipher_mult0_89);
  auto cipher_mult1_26 = cc->EvalMult(cipher_mult0_26, cipher_mult0_90);
  auto cipher_mult1_27 = cc->EvalMult(cipher_mult0_27, cipher_mult0_91);
  auto cipher_mult1_28 = cc->EvalMult(cipher_mult0_28, cipher_mult0_92);
  auto cipher_mult1_29 = cc->EvalMult(cipher_mult0_29, cipher_mult0_93);
  auto cipher_mult1_30 = cc->EvalMult(cipher_mult0_30, cipher_mult0_94);
  auto cipher_mult1_31 = cc->EvalMult(cipher_mult0_31, cipher_mult0_95);
  auto cipher_mult1_32 = cc->EvalMult(cipher_mult0_32, cipher_mult0_96);
  auto cipher_mult1_33 = cc->EvalMult(cipher_mult0_33, cipher_mult0_97);
  auto cipher_mult1_34 = cc->EvalMult(cipher_mult0_34, cipher_mult0_98);
  auto cipher_mult1_35 = cc->EvalMult(cipher_mult0_35, cipher_mult0_99);
  auto cipher_mult1_36 = cc->EvalMult(cipher_mult0_36, cipher_mult0_100);
  auto cipher_mult1_37 = cc->EvalMult(cipher_mult0_37, cipher_mult0_101);
  auto cipher_mult1_38 = cc->EvalMult(cipher_mult0_38, cipher_mult0_102);
  auto cipher_mult1_39 = cc->EvalMult(cipher_mult0_39, cipher_mult0_103);
  auto cipher_mult1_40 = cc->EvalMult(cipher_mult0_40, cipher_mult0_104);
  auto cipher_mult1_41 = cc->EvalMult(cipher_mult0_41, cipher_mult0_105);
  auto cipher_mult1_42 = cc->EvalMult(cipher_mult0_42, cipher_mult0_106);
  auto cipher_mult1_43 = cc->EvalMult(cipher_mult0_43, cipher_mult0_107);
  auto cipher_mult1_44 = cc->EvalMult(cipher_mult0_44, cipher_mult0_108);
  auto cipher_mult1_45 = cc->EvalMult(cipher_mult0_45, cipher_mult0_109);
  auto cipher_mult1_46 = cc->EvalMult(cipher_mult0_46, cipher_mult0_110);
  auto cipher_mult1_47 = cc->EvalMult(cipher_mult0_47, cipher_mult0_111);
  auto cipher_mult1_48 = cc->EvalMult(cipher_mult0_48, cipher_mult0_112);
  auto cipher_mult1_49 = cc->EvalMult(cipher_mult0_49, cipher_mult0_113);
  auto cipher_mult1_50 = cc->EvalMult(cipher_mult0_50, cipher_mult0_114);
  auto cipher_mult1_51 = cc->EvalMult(cipher_mult0_51, cipher_mult0_115);
  auto cipher_mult1_52 = cc->EvalMult(cipher_mult0_52, cipher_mult0_116);
  auto cipher_mult1_53 = cc->EvalMult(cipher_mult0_53, cipher_mult0_117);
  auto cipher_mult1_54 = cc->EvalMult(cipher_mult0_54, cipher_mult0_118);
  auto cipher_mult1_55 = cc->EvalMult(cipher_mult0_55, cipher_mult0_119);
  auto cipher_mult1_56 = cc->EvalMult(cipher_mult0_56, cipher_mult0_120);
  auto cipher_mult1_57 = cc->EvalMult(cipher_mult0_57, cipher_mult0_121);
  auto cipher_mult1_58 = cc->EvalMult(cipher_mult0_58, cipher_mult0_122);
  auto cipher_mult1_59 = cc->EvalMult(cipher_mult0_59, cipher_mult0_123);
  auto cipher_mult1_60 = cc->EvalMult(cipher_mult0_60, cipher_mult0_124);
  auto cipher_mult1_61 = cc->EvalMult(cipher_mult0_61, cipher_mult0_125);
  auto cipher_mult1_62 = cc->EvalMult(cipher_mult0_62, cipher_mult0_126);
  auto cipher_mult1_63 = cc->EvalMult(cipher_mult0_63, cipher_mult0_127);
  auto cipher_mult2_0 = cc->EvalMult(cipher_mult1_0, cipher_mult1_32);
  auto cipher_mult2_1 = cc->EvalMult(cipher_mult1_1, cipher_mult1_33);
  auto cipher_mult2_2 = cc->EvalMult(cipher_mult1_2, cipher_mult1_34);
  auto cipher_mult2_3 = cc->EvalMult(cipher_mult1_3, cipher_mult1_35);
  auto cipher_mult2_4 = cc->EvalMult(cipher_mult1_4, cipher_mult1_36);
  auto cipher_mult2_5 = cc->EvalMult(cipher_mult1_5, cipher_mult1_37);
  auto cipher_mult2_6 = cc->EvalMult(cipher_mult1_6, cipher_mult1_38);
  auto cipher_mult2_7 = cc->EvalMult(cipher_mult1_7, cipher_mult1_39);
  auto cipher_mult2_8 = cc->EvalMult(cipher_mult1_8, cipher_mult1_40);
  auto cipher_mult2_9 = cc->EvalMult(cipher_mult1_9, cipher_mult1_41);
  auto cipher_mult2_10 = cc->EvalMult(cipher_mult1_10, cipher_mult1_42);
  auto cipher_mult2_11 = cc->EvalMult(cipher_mult1_11, cipher_mult1_43);
  auto cipher_mult2_12 = cc->EvalMult(cipher_mult1_12, cipher_mult1_44);
  auto cipher_mult2_13 = cc->EvalMult(cipher_mult1_13, cipher_mult1_45);
  auto cipher_mult2_14 = cc->EvalMult(cipher_mult1_14, cipher_mult1_46);
  auto cipher_mult2_15 = cc->EvalMult(cipher_mult1_15, cipher_mult1_47);
  auto cipher_mult2_16 = cc->EvalMult(cipher_mult1_16, cipher_mult1_48);
  auto cipher_mult2_17 = cc->EvalMult(cipher_mult1_17, cipher_mult1_49);
  auto cipher_mult2_18 = cc->EvalMult(cipher_mult1_18, cipher_mult1_50);
  auto cipher_mult2_19 = cc->EvalMult(cipher_mult1_19, cipher_mult1_51);
  auto cipher_mult2_20 = cc->EvalMult(cipher_mult1_20, cipher_mult1_52);
  auto cipher_mult2_21 = cc->EvalMult(cipher_mult1_21, cipher_mult1_53);
  auto cipher_mult2_22 = cc->EvalMult(cipher_mult1_22, cipher_mult1_54);
  auto cipher_mult2_23 = cc->EvalMult(cipher_mult1_23, cipher_mult1_55);
  auto cipher_mult2_24 = cc->EvalMult(cipher_mult1_24, cipher_mult1_56);
  auto cipher_mult2_25 = cc->EvalMult(cipher_mult1_25, cipher_mult1_57);
  auto cipher_mult2_26 = cc->EvalMult(cipher_mult1_26, cipher_mult1_58);
  auto cipher_mult2_27 = cc->EvalMult(cipher_mult1_27, cipher_mult1_59);
  auto cipher_mult2_28 = cc->EvalMult(cipher_mult1_28, cipher_mult1_60);
  auto cipher_mult2_29 = cc->EvalMult(cipher_mult1_29, cipher_mult1_61);
  auto cipher_mult2_30 = cc->EvalMult(cipher_mult1_30, cipher_mult1_62);
  auto cipher_mult2_31 = cc->EvalMult(cipher_mult1_31, cipher_mult1_63);
  auto cipher_mult3_0 = cc->EvalMult(cipher_mult2_0, cipher_mult2_16);
  auto cipher_mult3_1 = cc->EvalMult(cipher_mult2_1, cipher_mult2_17);
  auto cipher_mult3_2 = cc->EvalMult(cipher_mult2_2, cipher_mult2_18);
  auto cipher_mult3_3 = cc->EvalMult(cipher_mult2_3, cipher_mult2_19);
  auto cipher_mult3_4 = cc->EvalMult(cipher_mult2_4, cipher_mult2_20);
  auto cipher_mult3_5 = cc->EvalMult(cipher_mult2_5, cipher_mult2_21);
  auto cipher_mult3_6 = cc->EvalMult(cipher_mult2_6, cipher_mult2_22);
  auto cipher_mult3_7 = cc->EvalMult(cipher_mult2_7, cipher_mult2_23);
  auto cipher_mult3_8 = cc->EvalMult(cipher_mult2_8, cipher_mult2_24);
  auto cipher_mult3_9 = cc->EvalMult(cipher_mult2_9, cipher_mult2_25);
  auto cipher_mult3_10 = cc->EvalMult(cipher_mult2_10, cipher_mult2_26);
  auto cipher_mult3_11 = cc->EvalMult(cipher_mult2_11, cipher_mult2_27);
  auto cipher_mult3_12 = cc->EvalMult(cipher_mult2_12, cipher_mult2_28);
  auto cipher_mult3_13 = cc->EvalMult(cipher_mult2_13, cipher_mult2_29);
  auto cipher_mult3_14 = cc->EvalMult(cipher_mult2_14, cipher_mult2_30);
  auto cipher_mult3_15 = cc->EvalMult(cipher_mult2_15, cipher_mult2_31);
  auto cipher_mult4_0 = cc->EvalMult(cipher_mult3_0, cipher_mult3_8);
  auto cipher_mult4_1 = cc->EvalMult(cipher_mult3_1, cipher_mult3_9);
  auto cipher_mult4_2 = cc->EvalMult(cipher_mult3_2, cipher_mult3_10);
  auto cipher_mult4_3 = cc->EvalMult(cipher_mult3_3, cipher_mult3_11);
  auto cipher_mult4_4 = cc->EvalMult(cipher_mult3_4, cipher_mult3_12);
  auto cipher_mult4_5 = cc->EvalMult(cipher_mult3_5, cipher_mult3_13);
  auto cipher_mult4_6 = cc->EvalMult(cipher_mult3_6, cipher_mult3_14);
  auto cipher_mult4_7 = cc->EvalMult(cipher_mult3_7, cipher_mult3_15);
  auto cipher_mult5_0 = cc->EvalMult(cipher_mult4_0, cipher_mult4_4);
  auto cipher_mult5_1 = cc->EvalMult(cipher_mult4_1, cipher_mult4_5);
  auto cipher_mult5_2 = cc->EvalMult(cipher_mult4_2, cipher_mult4_6);
  auto cipher_mult5_3 = cc->EvalMult(cipher_mult4_3, cipher_mult4_7);
  auto cipher_mult6_0 = cc->EvalMult(cipher_mult5_0, cipher_mult5_2);
  auto cipher_mult6_1 = cc->EvalMult(cipher_mult5_1, cipher_mult5_3);
  auto cipher_mult7_0 = cc->EvalMult(cipher_mult6_0, cipher_mult6_1);

  //Decrypting 
  vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
  auto ciphertextPartial0 = cc->MultipartyDecryptLead(kp1.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial0[0]);auto ciphertextPartial1 = cc->MultipartyDecryptMain(kp2.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  auto ciphertextPartial2 = cc->MultipartyDecryptMain(kp3.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
  auto ciphertextPartial3 = cc->MultipartyDecryptMain(kp4.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial3[0]);
  auto ciphertextPartial4 = cc->MultipartyDecryptMain(kp5.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial4[0]);
  auto ciphertextPartial5 = cc->MultipartyDecryptMain(kp6.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial5[0]);
  auto ciphertextPartial6 = cc->MultipartyDecryptMain(kp7.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial6[0]);
  auto ciphertextPartial7 = cc->MultipartyDecryptMain(kp8.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial7[0]);
  auto ciphertextPartial8 = cc->MultipartyDecryptMain(kp9.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial8[0]);
  auto ciphertextPartial9 = cc->MultipartyDecryptMain(kp10.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial9[0]);
  auto ciphertextPartial10 = cc->MultipartyDecryptMain(kp11.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial10[0]);
  auto ciphertextPartial11 = cc->MultipartyDecryptMain(kp12.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial11[0]);
  auto ciphertextPartial12 = cc->MultipartyDecryptMain(kp13.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial12[0]);
  auto ciphertextPartial13 = cc->MultipartyDecryptMain(kp14.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial13[0]);
  auto ciphertextPartial14 = cc->MultipartyDecryptMain(kp15.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial14[0]);
  auto ciphertextPartial15 = cc->MultipartyDecryptMain(kp16.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial15[0]);
  auto ciphertextPartial16 = cc->MultipartyDecryptMain(kp17.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial16[0]);
  auto ciphertextPartial17 = cc->MultipartyDecryptMain(kp18.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial17[0]);
  auto ciphertextPartial18 = cc->MultipartyDecryptMain(kp19.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial18[0]);
  auto ciphertextPartial19 = cc->MultipartyDecryptMain(kp20.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial19[0]);
  auto ciphertextPartial20 = cc->MultipartyDecryptMain(kp21.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial20[0]);
  auto ciphertextPartial21 = cc->MultipartyDecryptMain(kp22.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial21[0]);
  auto ciphertextPartial22 = cc->MultipartyDecryptMain(kp23.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial22[0]);
  auto ciphertextPartial23 = cc->MultipartyDecryptMain(kp24.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial23[0]);
  auto ciphertextPartial24 = cc->MultipartyDecryptMain(kp25.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial24[0]);
  auto ciphertextPartial25 = cc->MultipartyDecryptMain(kp26.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial25[0]);
  auto ciphertextPartial26 = cc->MultipartyDecryptMain(kp27.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial26[0]);
  auto ciphertextPartial27 = cc->MultipartyDecryptMain(kp28.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial27[0]);
  auto ciphertextPartial28 = cc->MultipartyDecryptMain(kp29.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial28[0]);
  auto ciphertextPartial29 = cc->MultipartyDecryptMain(kp30.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial29[0]);
  auto ciphertextPartial30 = cc->MultipartyDecryptMain(kp31.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial30[0]);
  auto ciphertextPartial31 = cc->MultipartyDecryptMain(kp32.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial31[0]);
  auto ciphertextPartial32 = cc->MultipartyDecryptMain(kp33.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial32[0]);
  auto ciphertextPartial33 = cc->MultipartyDecryptMain(kp34.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial33[0]);
  auto ciphertextPartial34 = cc->MultipartyDecryptMain(kp35.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial34[0]);
  auto ciphertextPartial35 = cc->MultipartyDecryptMain(kp36.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial35[0]);
  auto ciphertextPartial36 = cc->MultipartyDecryptMain(kp37.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial36[0]);
  auto ciphertextPartial37 = cc->MultipartyDecryptMain(kp38.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial37[0]);
  auto ciphertextPartial38 = cc->MultipartyDecryptMain(kp39.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial38[0]);
  auto ciphertextPartial39 = cc->MultipartyDecryptMain(kp40.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial39[0]);
  auto ciphertextPartial40 = cc->MultipartyDecryptMain(kp41.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial40[0]);
  auto ciphertextPartial41 = cc->MultipartyDecryptMain(kp42.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial41[0]);
  auto ciphertextPartial42 = cc->MultipartyDecryptMain(kp43.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial42[0]);
  auto ciphertextPartial43 = cc->MultipartyDecryptMain(kp44.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial43[0]);
  auto ciphertextPartial44 = cc->MultipartyDecryptMain(kp45.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial44[0]);
  auto ciphertextPartial45 = cc->MultipartyDecryptMain(kp46.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial45[0]);
  auto ciphertextPartial46 = cc->MultipartyDecryptMain(kp47.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial46[0]);
  auto ciphertextPartial47 = cc->MultipartyDecryptMain(kp48.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial47[0]);
  auto ciphertextPartial48 = cc->MultipartyDecryptMain(kp49.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial48[0]);
  auto ciphertextPartial49 = cc->MultipartyDecryptMain(kp50.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial49[0]);
  auto ciphertextPartial50 = cc->MultipartyDecryptMain(kp51.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial50[0]);
  auto ciphertextPartial51 = cc->MultipartyDecryptMain(kp52.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial51[0]);
  auto ciphertextPartial52 = cc->MultipartyDecryptMain(kp53.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial52[0]);
  auto ciphertextPartial53 = cc->MultipartyDecryptMain(kp54.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial53[0]);
  auto ciphertextPartial54 = cc->MultipartyDecryptMain(kp55.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial54[0]);
  auto ciphertextPartial55 = cc->MultipartyDecryptMain(kp56.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial55[0]);
  auto ciphertextPartial56 = cc->MultipartyDecryptMain(kp57.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial56[0]);
  auto ciphertextPartial57 = cc->MultipartyDecryptMain(kp58.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial57[0]);
  auto ciphertextPartial58 = cc->MultipartyDecryptMain(kp59.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial58[0]);
  auto ciphertextPartial59 = cc->MultipartyDecryptMain(kp60.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial59[0]);
  auto ciphertextPartial60 = cc->MultipartyDecryptMain(kp61.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial60[0]);
  auto ciphertextPartial61 = cc->MultipartyDecryptMain(kp62.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial61[0]);
  auto ciphertextPartial62 = cc->MultipartyDecryptMain(kp63.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial62[0]);
  auto ciphertextPartial63 = cc->MultipartyDecryptMain(kp64.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial63[0]);
  auto ciphertextPartial64 = cc->MultipartyDecryptMain(kp65.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial64[0]);
  auto ciphertextPartial65 = cc->MultipartyDecryptMain(kp66.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial65[0]);
  auto ciphertextPartial66 = cc->MultipartyDecryptMain(kp67.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial66[0]);
  auto ciphertextPartial67 = cc->MultipartyDecryptMain(kp68.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial67[0]);
  auto ciphertextPartial68 = cc->MultipartyDecryptMain(kp69.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial68[0]);
  auto ciphertextPartial69 = cc->MultipartyDecryptMain(kp70.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial69[0]);
  auto ciphertextPartial70 = cc->MultipartyDecryptMain(kp71.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial70[0]);
  auto ciphertextPartial71 = cc->MultipartyDecryptMain(kp72.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial71[0]);
  auto ciphertextPartial72 = cc->MultipartyDecryptMain(kp73.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial72[0]);
  auto ciphertextPartial73 = cc->MultipartyDecryptMain(kp74.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial73[0]);
  auto ciphertextPartial74 = cc->MultipartyDecryptMain(kp75.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial74[0]);
  auto ciphertextPartial75 = cc->MultipartyDecryptMain(kp76.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial75[0]);
  auto ciphertextPartial76 = cc->MultipartyDecryptMain(kp77.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial76[0]);
  auto ciphertextPartial77 = cc->MultipartyDecryptMain(kp78.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial77[0]);
  auto ciphertextPartial78 = cc->MultipartyDecryptMain(kp79.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial78[0]);
  auto ciphertextPartial79 = cc->MultipartyDecryptMain(kp80.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial79[0]);
  auto ciphertextPartial80 = cc->MultipartyDecryptMain(kp81.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial80[0]);
  auto ciphertextPartial81 = cc->MultipartyDecryptMain(kp82.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial81[0]);
  auto ciphertextPartial82 = cc->MultipartyDecryptMain(kp83.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial82[0]);
  auto ciphertextPartial83 = cc->MultipartyDecryptMain(kp84.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial83[0]);
  auto ciphertextPartial84 = cc->MultipartyDecryptMain(kp85.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial84[0]);
  auto ciphertextPartial85 = cc->MultipartyDecryptMain(kp86.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial85[0]);
  auto ciphertextPartial86 = cc->MultipartyDecryptMain(kp87.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial86[0]);
  auto ciphertextPartial87 = cc->MultipartyDecryptMain(kp88.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial87[0]);
  auto ciphertextPartial88 = cc->MultipartyDecryptMain(kp89.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial88[0]);
  auto ciphertextPartial89 = cc->MultipartyDecryptMain(kp90.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial89[0]);
  auto ciphertextPartial90 = cc->MultipartyDecryptMain(kp91.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial90[0]);
  auto ciphertextPartial91 = cc->MultipartyDecryptMain(kp92.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial91[0]);
  auto ciphertextPartial92 = cc->MultipartyDecryptMain(kp93.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial92[0]);
  auto ciphertextPartial93 = cc->MultipartyDecryptMain(kp94.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial93[0]);
  auto ciphertextPartial94 = cc->MultipartyDecryptMain(kp95.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial94[0]);
  auto ciphertextPartial95 = cc->MultipartyDecryptMain(kp96.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial95[0]);
  auto ciphertextPartial96 = cc->MultipartyDecryptMain(kp97.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial96[0]);
  auto ciphertextPartial97 = cc->MultipartyDecryptMain(kp98.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial97[0]);
  auto ciphertextPartial98 = cc->MultipartyDecryptMain(kp99.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial98[0]);
  auto ciphertextPartial99 = cc->MultipartyDecryptMain(kp100.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial99[0]);
  auto ciphertextPartial100 = cc->MultipartyDecryptMain(kp101.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial100[0]);
  auto ciphertextPartial101 = cc->MultipartyDecryptMain(kp102.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial101[0]);
  auto ciphertextPartial102 = cc->MultipartyDecryptMain(kp103.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial102[0]);
  auto ciphertextPartial103 = cc->MultipartyDecryptMain(kp104.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial103[0]);
  auto ciphertextPartial104 = cc->MultipartyDecryptMain(kp105.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial104[0]);
  auto ciphertextPartial105 = cc->MultipartyDecryptMain(kp106.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial105[0]);
  auto ciphertextPartial106 = cc->MultipartyDecryptMain(kp107.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial106[0]);
  auto ciphertextPartial107 = cc->MultipartyDecryptMain(kp108.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial107[0]);
  auto ciphertextPartial108 = cc->MultipartyDecryptMain(kp109.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial108[0]);
  auto ciphertextPartial109 = cc->MultipartyDecryptMain(kp110.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial109[0]);
  auto ciphertextPartial110 = cc->MultipartyDecryptMain(kp111.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial110[0]);
  auto ciphertextPartial111 = cc->MultipartyDecryptMain(kp112.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial111[0]);
  auto ciphertextPartial112 = cc->MultipartyDecryptMain(kp113.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial112[0]);
  auto ciphertextPartial113 = cc->MultipartyDecryptMain(kp114.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial113[0]);
  auto ciphertextPartial114 = cc->MultipartyDecryptMain(kp115.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial114[0]);
  auto ciphertextPartial115 = cc->MultipartyDecryptMain(kp116.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial115[0]);
  auto ciphertextPartial116 = cc->MultipartyDecryptMain(kp117.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial116[0]);
  auto ciphertextPartial117 = cc->MultipartyDecryptMain(kp118.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial117[0]);
  auto ciphertextPartial118 = cc->MultipartyDecryptMain(kp119.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial118[0]);
  auto ciphertextPartial119 = cc->MultipartyDecryptMain(kp120.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial119[0]);
  auto ciphertextPartial120 = cc->MultipartyDecryptMain(kp121.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial120[0]);
  auto ciphertextPartial121 = cc->MultipartyDecryptMain(kp122.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial121[0]);
  auto ciphertextPartial122 = cc->MultipartyDecryptMain(kp123.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial122[0]);
  auto ciphertextPartial123 = cc->MultipartyDecryptMain(kp124.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial123[0]);
  auto ciphertextPartial124 = cc->MultipartyDecryptMain(kp125.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial124[0]);
  auto ciphertextPartial125 = cc->MultipartyDecryptMain(kp126.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial125[0]);
  auto ciphertextPartial126 = cc->MultipartyDecryptMain(kp127.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial126[0]);
  auto ciphertextPartial127 = cc->MultipartyDecryptMain(kp128.secretKey, {cipher_mult7_0});
  partialCiphertextVecMult.push_back(ciphertextPartial127[0]);

  Plaintext plaintextMultipartyMult;
  cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

  plaintextMultipartyMult->SetLength(plaintext0->GetLength());
  cout << "\n Resulting Fused Plaintext after Multiplication of plaintexts 1 "
          "and 3: \n"
       << endl;
  cout << plaintextMultipartyMult << endl;


}



std::vector<std::vector<int64_t>> FetchSketches(int hospital_number){
  static int COLS = 32;
  std::string f_path = std::__fs::filesystem::current_path().string() + "/sim_sketches/hospital_" + std::to_string(hospital_number) +"_sketches.csv";
  std::cout << "\n=========== Looking for hospital sketch at " + f_path+
             " ====================="
          << std::endl;
  // Variable declarations
  fstream myfile;
  std::string line, coname;
  std::vector<std::vector<int64_t>>sketch_buckets; // 2d array as a vector of vectors
  vector<int64_t> rowVector(COLS); // vector to add into 'array' (represents a row)
  int row = 0; // Row counter
  int colIdx;
  int64_t val;
  // Read file
  myfile.open(f_path, ios::in); // Open file
  if (myfile.is_open()) { // If file has correctly opened...
    // Output debug message
    cout << "File correctly opened" << endl;

    // Dynamically store data into array
    while (myfile.good()) { // ... and while there are no errors,
      while(std::getline(myfile, line)){
        std::stringstream s(line);
        colIdx = 0;
        while(s >> val){
          rowVector[colIdx] =val;
          if(s.peek() == ',') s.ignore();
          colIdx++;
        }
        sketch_buckets.push_back(rowVector);
        row++; // Keep track of actual row 
      }
    }
  }
  else cout << "Unable to open file" << endl;
  /*
  std::cout << "Data for hospital " << std::to_string(hospital_number) << std::endl;
  for (int i =0; i < 4; i++){
    for (int j=0; j < 32; j++){
      std::cout << std::to_string(sketch_buckets[i][j]) << " ";
    }
    std::cout << std::endl;
  }
  */

  return sketch_buckets;
}



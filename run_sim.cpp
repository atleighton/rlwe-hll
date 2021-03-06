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


void RunHLLSketch(std::vector<std::vector<std::vector<int64_t>>> hospital_sketches, int num_hospitals, int num_buckets, std::string sketch_dir);
std::vector<std::vector<int64_t>> FetchSketches(int hospital_number, std::string sketch_dir);




int main(int argc, char *argv[]) {
  int num_patients= atoi(argv[1]);
  int num_conditions = atoi(argv[2]);
  int num_hospitals = atoi(argv[3]);
  int num_buckets = atoi(argv[4]);
  std::string sketch_dir = argv[5];
  std::cout << num_patients << std::endl;
  std::cout << num_conditions << std::endl;
  std::cout << num_hospitals << std::endl;
  std::cout << num_buckets << std::endl;
  std::cout << sketch_dir << std::endl;

  // load all sketches into 3d array. array[hospital number][bucket number] yields the unary sketch vector
  std::vector<std::vector<std::vector<int64_t>>> hospital_sketches;
  for (int hospital_number = 1; hospital_number <= num_hospitals; hospital_number++){
    hospital_sketches.push_back(FetchSketches(hospital_number, sketch_dir));
  }


  std::cout << "\n=================RUNNING FOR HLL Sketches====================="
          << std::endl;

  RunHLLSketch(hospital_sketches, num_hospitals, num_buckets, sketch_dir);

  return 0;
}



void RunHLLSketch(std::vector<std::vector<std::vector<int64_t>>> hospital_sketches, int num_hospitals, int num_buckets, std::string sketch_dir) {
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

//initialize public key container for 8 parties 
/*
LPKeyPair<DCRTPoly> kp1;
LPKeyPair<DCRTPoly> kp2;
LPKeyPair<DCRTPoly> kp3;
LPKeyPair<DCRTPoly> kp4;
LPKeyPair<DCRTPoly> kp5;
LPKeyPair<DCRTPoly> kp6;
LPKeyPair<DCRTPoly> kp7;
LPKeyPair<DCRTPoly> kp8;
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
auto evalMult_up_to_3 = cc->MultiAddEvalKeys(evalMult_up_to_2, evalMultKey3, kp3.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp3.secretKey);
auto evalSumKeys3 = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysJoin_to_2, kp3.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_3 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_2, evalSumKeys3, kp3.publicKey->GetKeyTag());

//gen keys party 4
kp4 = cc->MultipartyKeyGen(kp3.publicKey);

// Generate evalmult key part for party 4
auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMult_up_to_3);
auto evalMult_up_to_4 = cc->MultiAddEvalKeys(evalMult_up_to_3, evalMultKey4, kp4.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp4.secretKey);
auto evalSumKeys4 = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeysJoin_to_3, kp4.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_4 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_3, evalSumKeys4, kp4.publicKey->GetKeyTag());

//gen keys party 5
kp5 = cc->MultipartyKeyGen(kp4.publicKey);

// Generate evalmult key part for party 5
auto evalMultKey5 = cc->MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMult_up_to_4);
auto evalMult_up_to_5 = cc->MultiAddEvalKeys(evalMult_up_to_4, evalMultKey5, kp5.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp5.secretKey);
auto evalSumKeys5 = cc->MultiEvalSumKeyGen(kp5.secretKey, evalSumKeysJoin_to_4, kp5.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_5 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_4, evalSumKeys5, kp5.publicKey->GetKeyTag());

//gen keys party 6
kp6 = cc->MultipartyKeyGen(kp5.publicKey);

// Generate evalmult key part for party 6
auto evalMultKey6 = cc->MultiKeySwitchGen(kp6.secretKey, kp6.secretKey, evalMult_up_to_5);
auto evalMult_up_to_6 = cc->MultiAddEvalKeys(evalMult_up_to_5, evalMultKey6, kp6.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp6.secretKey);
auto evalSumKeys6 = cc->MultiEvalSumKeyGen(kp6.secretKey, evalSumKeysJoin_to_5, kp6.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_6 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_5, evalSumKeys6, kp6.publicKey->GetKeyTag());

//gen keys party 7
kp7 = cc->MultipartyKeyGen(kp6.publicKey);

// Generate evalmult key part for party 7
auto evalMultKey7 = cc->MultiKeySwitchGen(kp7.secretKey, kp7.secretKey, evalMult_up_to_6);
auto evalMult_up_to_7 = cc->MultiAddEvalKeys(evalMult_up_to_6, evalMultKey7, kp7.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp7.secretKey);
auto evalSumKeys7 = cc->MultiEvalSumKeyGen(kp7.secretKey, evalSumKeysJoin_to_6, kp7.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_7 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_6, evalSumKeys7, kp7.publicKey->GetKeyTag());

//gen keys party 8
kp8 = cc->MultipartyKeyGen(kp7.publicKey);

// Generate evalmult key part for party 8
auto evalMultKey8 = cc->MultiKeySwitchGen(kp8.secretKey, kp8.secretKey, evalMult_up_to_7);
auto evalMult_up_to_8 = cc->MultiAddEvalKeys(evalMult_up_to_7, evalMultKey8, kp8.publicKey->GetKeyTag());



std::cout << "First mult key gen done " << depth << std::endl;


// gen eval sum keys
cc->EvalSumKeyGen(kp8.secretKey);
auto evalSumKeys8 = cc->MultiEvalSumKeyGen(kp8.secretKey, evalSumKeysJoin_to_7, kp8.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_8 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_7, evalSumKeys8, kp8.publicKey->GetKeyTag());


auto evalMultJoint1 = cc->MultiMultEvalKey(evalMult_up_to_8, kp1.secretKey, kp8.publicKey->GetKeyTag());

auto evalMultJoint2 = cc->MultiMultEvalKey(evalMult_up_to_8, kp2.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial2 = cc->MultiAddEvalMultKeys(evalMultJoint1, evalMultJoint2, kp8.publicKey->GetKeyTag());


auto evalMultJoint3 = cc->MultiMultEvalKey(evalMult_up_to_8, kp3.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial3 = cc->MultiAddEvalMultKeys(evalMultPartial2, evalMultJoint3, kp8.publicKey->GetKeyTag());


auto evalMultJoint4 = cc->MultiMultEvalKey(evalMult_up_to_8, kp4.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial4 = cc->MultiAddEvalMultKeys(evalMultPartial3, evalMultJoint4, kp8.publicKey->GetKeyTag());


auto evalMultJoint5 = cc->MultiMultEvalKey(evalMult_up_to_8, kp5.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial5 = cc->MultiAddEvalMultKeys(evalMultPartial4, evalMultJoint5, kp8.publicKey->GetKeyTag());


auto evalMultJoint6 = cc->MultiMultEvalKey(evalMult_up_to_8, kp6.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial6 = cc->MultiAddEvalMultKeys(evalMultPartial5, evalMultJoint6, kp8.publicKey->GetKeyTag());


auto evalMultJoint7 = cc->MultiMultEvalKey(evalMult_up_to_8, kp7.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial7 = cc->MultiAddEvalMultKeys(evalMultPartial6, evalMultJoint7, kp8.publicKey->GetKeyTag());

auto evalMultJoint8 = cc->MultiMultEvalKey(evalMult_up_to_8, kp8.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial8 = cc->MultiAddEvalMultKeys(evalMultPartial7, evalMultJoint8, kp8.publicKey->GetKeyTag());


std::cout << "Eval mult joining done" << depth << std::endl;


// insert final mult key
cc->InsertEvalMultKey({evalMultPartial8});

// insert final sum key 
cc->InsertEvalSumKey(evalSumKeysJoin_to_8);
std::cout << "Keys generated!" << std::endl;


std::cout << "Inserting keys" << depth << std::endl;

vector<Ciphertext<DCRTPoly>> ciphertexts;

Plaintext plaintext0 = cc->MakePackedPlaintext(hospital_sketches[0][0]);
Ciphertext<DCRTPoly> cipher_mult0_0;
cipher_mult0_0 = cc->Encrypt(kp8.publicKey, plaintext0);
ciphertexts.push_back(cipher_mult0_0);

Plaintext plaintext1 = cc->MakePackedPlaintext(hospital_sketches[1][0]);
Ciphertext<DCRTPoly> cipher_mult0_1;
cipher_mult0_1 = cc->Encrypt(kp8.publicKey, plaintext1);
ciphertexts.push_back(cipher_mult0_1);

Plaintext plaintext2 = cc->MakePackedPlaintext(hospital_sketches[2][0]);
Ciphertext<DCRTPoly> cipher_mult0_2;
cipher_mult0_2 = cc->Encrypt(kp8.publicKey, plaintext2);
ciphertexts.push_back(cipher_mult0_2);

Plaintext plaintext3 = cc->MakePackedPlaintext(hospital_sketches[3][0]);
Ciphertext<DCRTPoly> cipher_mult0_3;
cipher_mult0_3 = cc->Encrypt(kp8.publicKey, plaintext3);
ciphertexts.push_back(cipher_mult0_3);

Plaintext plaintext4 = cc->MakePackedPlaintext(hospital_sketches[4][0]);
Ciphertext<DCRTPoly> cipher_mult0_4;
cipher_mult0_4 = cc->Encrypt(kp8.publicKey, plaintext4);
ciphertexts.push_back(cipher_mult0_4);

Plaintext plaintext5 = cc->MakePackedPlaintext(hospital_sketches[5][0]);
Ciphertext<DCRTPoly> cipher_mult0_5;
cipher_mult0_5 = cc->Encrypt(kp8.publicKey, plaintext5);
ciphertexts.push_back(cipher_mult0_5);

Plaintext plaintext6 = cc->MakePackedPlaintext(hospital_sketches[6][0]);
Ciphertext<DCRTPoly> cipher_mult0_6;
cipher_mult0_6 = cc->Encrypt(kp8.publicKey, plaintext6);
ciphertexts.push_back(cipher_mult0_6);

Plaintext plaintext7 = cc->MakePackedPlaintext(hospital_sketches[7][0]);
Ciphertext<DCRTPoly> cipher_mult0_7;
cipher_mult0_7 = cc->Encrypt(kp8.publicKey, plaintext7);
ciphertexts.push_back(cipher_mult0_7);


std::cout << " Loaded plaintexts " << depth << std::endl;



std::cout << "Preforming multiplication " << depth << std::endl;

// Tree mult - final product stored in cipher_mult0
std::cout << "Round 1 mults" << depth << std::endl;
auto cipher_mult1_0 = cc->EvalMult(cipher_mult0_0, cipher_mult0_4);
std::cout << "0000000000 " << depth << std::endl;
auto cipher_mult1_1 = cc->EvalMult(cipher_mult0_1, cipher_mult0_5);
auto cipher_mult1_2 = cc->EvalMult(cipher_mult0_2, cipher_mult0_6);
auto cipher_mult1_3 = cc->EvalMult(cipher_mult0_3, cipher_mult0_7);
std::cout << "Round 2 mults" << depth << std::endl;
auto cipher_mult2_0 = cc->EvalMult(cipher_mult1_0, cipher_mult1_2);
auto cipher_mult2_1 = cc->EvalMult(cipher_mult1_1, cipher_mult1_3);
auto cipher_mult3_0 = cc->EvalMult(cipher_mult2_0, cipher_mult2_1);


  std::cout << "decrypting" << depth << std::endl;

//Decrypting 
vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
auto ciphertextPartial0 = cc->MultipartyDecryptLead(kp1.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial0[0]);auto ciphertextPartial1 = cc->MultipartyDecryptMain(kp2.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
auto ciphertextPartial2 = cc->MultipartyDecryptMain(kp3.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
auto ciphertextPartial3 = cc->MultipartyDecryptMain(kp4.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial3[0]);
auto ciphertextPartial4 = cc->MultipartyDecryptMain(kp5.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial4[0]);
auto ciphertextPartial5 = cc->MultipartyDecryptMain(kp6.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial5[0]);
auto ciphertextPartial6 = cc->MultipartyDecryptMain(kp7.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial6[0]);
auto ciphertextPartial7 = cc->MultipartyDecryptMain(kp8.secretKey, {cipher_mult3_0});
partialCiphertextVecMult.push_back(ciphertextPartial7[0]);

Plaintext plaintextMultipartyMult;

cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

plaintextMultipartyMult->SetLength(plaintext0->GetLength());
cout << plaintextMultipartyMult << endl;
*/

//initialize public key container for 8 parties 


//initialize public key container for 8 parties 
LPKeyPair<DCRTPoly> kp1;
LPKeyPair<DCRTPoly> kp2;
LPKeyPair<DCRTPoly> kp3;
LPKeyPair<DCRTPoly> kp4;
LPKeyPair<DCRTPoly> kp5;
LPKeyPair<DCRTPoly> kp6;
LPKeyPair<DCRTPoly> kp7;
LPKeyPair<DCRTPoly> kp8;
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
auto evalMult_up_to_3 = cc->MultiAddEvalKeys(evalMult_up_to_2, evalMultKey3, kp3.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp3.secretKey);
auto evalSumKeys3 = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysJoin_to_2, kp3.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_3 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_2, evalSumKeys3, kp3.publicKey->GetKeyTag());

//gen keys party 4
kp4 = cc->MultipartyKeyGen(kp3.publicKey);

// Generate evalmult key part for party 4
auto evalMultKey4 = cc->MultiKeySwitchGen(kp4.secretKey, kp4.secretKey, evalMult_up_to_3);
auto evalMult_up_to_4 = cc->MultiAddEvalKeys(evalMult_up_to_3, evalMultKey4, kp4.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp4.secretKey);
auto evalSumKeys4 = cc->MultiEvalSumKeyGen(kp4.secretKey, evalSumKeysJoin_to_3, kp4.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_4 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_3, evalSumKeys4, kp4.publicKey->GetKeyTag());

//gen keys party 5
kp5 = cc->MultipartyKeyGen(kp4.publicKey);

// Generate evalmult key part for party 5
auto evalMultKey5 = cc->MultiKeySwitchGen(kp5.secretKey, kp5.secretKey, evalMult_up_to_4);
auto evalMult_up_to_5 = cc->MultiAddEvalKeys(evalMult_up_to_4, evalMultKey5, kp5.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp5.secretKey);
auto evalSumKeys5 = cc->MultiEvalSumKeyGen(kp5.secretKey, evalSumKeysJoin_to_4, kp5.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_5 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_4, evalSumKeys5, kp5.publicKey->GetKeyTag());

//gen keys party 6
kp6 = cc->MultipartyKeyGen(kp5.publicKey);

// Generate evalmult key part for party 6
auto evalMultKey6 = cc->MultiKeySwitchGen(kp6.secretKey, kp6.secretKey, evalMult_up_to_5);
auto evalMult_up_to_6 = cc->MultiAddEvalKeys(evalMult_up_to_5, evalMultKey6, kp6.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp6.secretKey);
auto evalSumKeys6 = cc->MultiEvalSumKeyGen(kp6.secretKey, evalSumKeysJoin_to_5, kp6.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_6 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_5, evalSumKeys6, kp6.publicKey->GetKeyTag());

//gen keys party 7
kp7 = cc->MultipartyKeyGen(kp6.publicKey);

// Generate evalmult key part for party 7
auto evalMultKey7 = cc->MultiKeySwitchGen(kp7.secretKey, kp7.secretKey, evalMult_up_to_6);
auto evalMult_up_to_7 = cc->MultiAddEvalKeys(evalMult_up_to_6, evalMultKey7, kp7.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp7.secretKey);
auto evalSumKeys7 = cc->MultiEvalSumKeyGen(kp7.secretKey, evalSumKeysJoin_to_6, kp7.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_7 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_6, evalSumKeys7, kp7.publicKey->GetKeyTag());

//gen keys party 8
kp8 = cc->MultipartyKeyGen(kp7.publicKey);

// Generate evalmult key part for party 8
auto evalMultKey8 = cc->MultiKeySwitchGen(kp8.secretKey, kp8.secretKey, evalMult_up_to_7);
auto evalMult_up_to_8 = cc->MultiAddEvalKeys(evalMult_up_to_7, evalMultKey8, kp8.publicKey->GetKeyTag());

// gen eval sum keys
cc->EvalSumKeyGen(kp8.secretKey);
auto evalSumKeys8 = cc->MultiEvalSumKeyGen(kp8.secretKey, evalSumKeysJoin_to_7, kp8.publicKey->GetKeyTag());
auto evalSumKeysJoin_to_8 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_7, evalSumKeys8, kp8.publicKey->GetKeyTag());
auto evalMultJoint1 = cc->MultiMultEvalKey(evalMult_up_to_8, kp1.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultJoint2 = cc->MultiMultEvalKey(evalMult_up_to_8, kp2.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial2 = cc->MultiAddEvalMultKeys(evalMultJoint1, evalMultJoint2, kp8.publicKey->GetKeyTag());
auto evalMultJoint3 = cc->MultiMultEvalKey(evalMult_up_to_8, kp3.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial3 = cc->MultiAddEvalMultKeys(evalMultPartial2, evalMultJoint3, kp8.publicKey->GetKeyTag());
auto evalMultJoint4 = cc->MultiMultEvalKey(evalMult_up_to_8, kp4.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial4 = cc->MultiAddEvalMultKeys(evalMultPartial3, evalMultJoint4, kp8.publicKey->GetKeyTag());
auto evalMultJoint5 = cc->MultiMultEvalKey(evalMult_up_to_8, kp5.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial5 = cc->MultiAddEvalMultKeys(evalMultPartial4, evalMultJoint5, kp8.publicKey->GetKeyTag());
auto evalMultJoint6 = cc->MultiMultEvalKey(evalMult_up_to_8, kp6.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial6 = cc->MultiAddEvalMultKeys(evalMultPartial5, evalMultJoint6, kp8.publicKey->GetKeyTag());
auto evalMultJoint7 = cc->MultiMultEvalKey(evalMult_up_to_8, kp7.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial7 = cc->MultiAddEvalMultKeys(evalMultPartial6, evalMultJoint7, kp8.publicKey->GetKeyTag());
auto evalMultJoint8 = cc->MultiMultEvalKey(evalMult_up_to_8, kp8.secretKey, kp8.publicKey->GetKeyTag());
auto evalMultPartial8 = cc->MultiAddEvalMultKeys(evalMultPartial7, evalMultJoint8, kp8.publicKey->GetKeyTag());

// insert final mult key
cc->InsertEvalMultKey({evalMultPartial8});

// insert final sum key 
cc->InsertEvalSumKey(evalSumKeysJoin_to_8);
std::cout << "Keys generated!" << std::endl;

Plaintext plaintext0_0 = cc->MakePackedPlaintext(hospital_sketches[0][0]);
Ciphertext<DCRTPoly> cipher_mult0_0_0;
cipher_mult0_0_0 = cc->Encrypt(kp8.publicKey, plaintext0_0);

Plaintext plaintext0_1 = cc->MakePackedPlaintext(hospital_sketches[0][1]);
Ciphertext<DCRTPoly> cipher_mult0_0_1;
cipher_mult0_0_1 = cc->Encrypt(kp8.publicKey, plaintext0_1);

Plaintext plaintext0_2 = cc->MakePackedPlaintext(hospital_sketches[0][2]);
Ciphertext<DCRTPoly> cipher_mult0_0_2;
cipher_mult0_0_2 = cc->Encrypt(kp8.publicKey, plaintext0_2);

Plaintext plaintext0_3 = cc->MakePackedPlaintext(hospital_sketches[0][3]);
Ciphertext<DCRTPoly> cipher_mult0_0_3;
cipher_mult0_0_3 = cc->Encrypt(kp8.publicKey, plaintext0_3);

Plaintext plaintext1_0 = cc->MakePackedPlaintext(hospital_sketches[1][0]);
Ciphertext<DCRTPoly> cipher_mult0_1_0;
cipher_mult0_1_0 = cc->Encrypt(kp8.publicKey, plaintext1_0);

Plaintext plaintext1_1 = cc->MakePackedPlaintext(hospital_sketches[1][1]);
Ciphertext<DCRTPoly> cipher_mult0_1_1;
cipher_mult0_1_1 = cc->Encrypt(kp8.publicKey, plaintext1_1);

Plaintext plaintext1_2 = cc->MakePackedPlaintext(hospital_sketches[1][2]);
Ciphertext<DCRTPoly> cipher_mult0_1_2;
cipher_mult0_1_2 = cc->Encrypt(kp8.publicKey, plaintext1_2);

Plaintext plaintext1_3 = cc->MakePackedPlaintext(hospital_sketches[1][3]);
Ciphertext<DCRTPoly> cipher_mult0_1_3;
cipher_mult0_1_3 = cc->Encrypt(kp8.publicKey, plaintext1_3);

Plaintext plaintext2_0 = cc->MakePackedPlaintext(hospital_sketches[2][0]);
Ciphertext<DCRTPoly> cipher_mult0_2_0;
cipher_mult0_2_0 = cc->Encrypt(kp8.publicKey, plaintext2_0);

Plaintext plaintext2_1 = cc->MakePackedPlaintext(hospital_sketches[2][1]);
Ciphertext<DCRTPoly> cipher_mult0_2_1;
cipher_mult0_2_1 = cc->Encrypt(kp8.publicKey, plaintext2_1);

Plaintext plaintext2_2 = cc->MakePackedPlaintext(hospital_sketches[2][2]);
Ciphertext<DCRTPoly> cipher_mult0_2_2;
cipher_mult0_2_2 = cc->Encrypt(kp8.publicKey, plaintext2_2);

Plaintext plaintext2_3 = cc->MakePackedPlaintext(hospital_sketches[2][3]);
Ciphertext<DCRTPoly> cipher_mult0_2_3;
cipher_mult0_2_3 = cc->Encrypt(kp8.publicKey, plaintext2_3);

Plaintext plaintext3_0 = cc->MakePackedPlaintext(hospital_sketches[3][0]);
Ciphertext<DCRTPoly> cipher_mult0_3_0;
cipher_mult0_3_0 = cc->Encrypt(kp8.publicKey, plaintext3_0);

Plaintext plaintext3_1 = cc->MakePackedPlaintext(hospital_sketches[3][1]);
Ciphertext<DCRTPoly> cipher_mult0_3_1;
cipher_mult0_3_1 = cc->Encrypt(kp8.publicKey, plaintext3_1);

Plaintext plaintext3_2 = cc->MakePackedPlaintext(hospital_sketches[3][2]);
Ciphertext<DCRTPoly> cipher_mult0_3_2;
cipher_mult0_3_2 = cc->Encrypt(kp8.publicKey, plaintext3_2);

Plaintext plaintext3_3 = cc->MakePackedPlaintext(hospital_sketches[3][3]);
Ciphertext<DCRTPoly> cipher_mult0_3_3;
cipher_mult0_3_3 = cc->Encrypt(kp8.publicKey, plaintext3_3);

Plaintext plaintext4_0 = cc->MakePackedPlaintext(hospital_sketches[4][0]);
Ciphertext<DCRTPoly> cipher_mult0_4_0;
cipher_mult0_4_0 = cc->Encrypt(kp8.publicKey, plaintext4_0);

Plaintext plaintext4_1 = cc->MakePackedPlaintext(hospital_sketches[4][1]);
Ciphertext<DCRTPoly> cipher_mult0_4_1;
cipher_mult0_4_1 = cc->Encrypt(kp8.publicKey, plaintext4_1);

Plaintext plaintext4_2 = cc->MakePackedPlaintext(hospital_sketches[4][2]);
Ciphertext<DCRTPoly> cipher_mult0_4_2;
cipher_mult0_4_2 = cc->Encrypt(kp8.publicKey, plaintext4_2);

Plaintext plaintext4_3 = cc->MakePackedPlaintext(hospital_sketches[4][3]);
Ciphertext<DCRTPoly> cipher_mult0_4_3;
cipher_mult0_4_3 = cc->Encrypt(kp8.publicKey, plaintext4_3);

Plaintext plaintext5_0 = cc->MakePackedPlaintext(hospital_sketches[5][0]);
Ciphertext<DCRTPoly> cipher_mult0_5_0;
cipher_mult0_5_0 = cc->Encrypt(kp8.publicKey, plaintext5_0);

Plaintext plaintext5_1 = cc->MakePackedPlaintext(hospital_sketches[5][1]);
Ciphertext<DCRTPoly> cipher_mult0_5_1;
cipher_mult0_5_1 = cc->Encrypt(kp8.publicKey, plaintext5_1);

Plaintext plaintext5_2 = cc->MakePackedPlaintext(hospital_sketches[5][2]);
Ciphertext<DCRTPoly> cipher_mult0_5_2;
cipher_mult0_5_2 = cc->Encrypt(kp8.publicKey, plaintext5_2);

Plaintext plaintext5_3 = cc->MakePackedPlaintext(hospital_sketches[5][3]);
Ciphertext<DCRTPoly> cipher_mult0_5_3;
cipher_mult0_5_3 = cc->Encrypt(kp8.publicKey, plaintext5_3);

Plaintext plaintext6_0 = cc->MakePackedPlaintext(hospital_sketches[6][0]);
Ciphertext<DCRTPoly> cipher_mult0_6_0;
cipher_mult0_6_0 = cc->Encrypt(kp8.publicKey, plaintext6_0);

Plaintext plaintext6_1 = cc->MakePackedPlaintext(hospital_sketches[6][1]);
Ciphertext<DCRTPoly> cipher_mult0_6_1;
cipher_mult0_6_1 = cc->Encrypt(kp8.publicKey, plaintext6_1);

Plaintext plaintext6_2 = cc->MakePackedPlaintext(hospital_sketches[6][2]);
Ciphertext<DCRTPoly> cipher_mult0_6_2;
cipher_mult0_6_2 = cc->Encrypt(kp8.publicKey, plaintext6_2);

Plaintext plaintext6_3 = cc->MakePackedPlaintext(hospital_sketches[6][3]);
Ciphertext<DCRTPoly> cipher_mult0_6_3;
cipher_mult0_6_3 = cc->Encrypt(kp8.publicKey, plaintext6_3);

Plaintext plaintext7_0 = cc->MakePackedPlaintext(hospital_sketches[7][0]);
Ciphertext<DCRTPoly> cipher_mult0_7_0;
cipher_mult0_7_0 = cc->Encrypt(kp8.publicKey, plaintext7_0);

Plaintext plaintext7_1 = cc->MakePackedPlaintext(hospital_sketches[7][1]);
Ciphertext<DCRTPoly> cipher_mult0_7_1;
cipher_mult0_7_1 = cc->Encrypt(kp8.publicKey, plaintext7_1);

Plaintext plaintext7_2 = cc->MakePackedPlaintext(hospital_sketches[7][2]);
Ciphertext<DCRTPoly> cipher_mult0_7_2;
cipher_mult0_7_2 = cc->Encrypt(kp8.publicKey, plaintext7_2);

Plaintext plaintext7_3 = cc->MakePackedPlaintext(hospital_sketches[7][3]);
Ciphertext<DCRTPoly> cipher_mult0_7_3;
cipher_mult0_7_3 = cc->Encrypt(kp8.publicKey, plaintext7_3);

// Tree mult - final product stored in cipher_mult_{depth}_0_{bucket}

// Intermediate format cipher_mult_{round#}_{node of tree#}_{bucket#}
// Tree mult - final product stored in cipher_mult0
auto cipher_mult1_0_0 = cc->EvalMult(cipher_mult0_0_0, cipher_mult0_4_0);
auto cipher_mult1_1_0 = cc->EvalMult(cipher_mult0_1_0, cipher_mult0_5_0);
auto cipher_mult1_2_0 = cc->EvalMult(cipher_mult0_2_0, cipher_mult0_6_0);
auto cipher_mult1_3_0 = cc->EvalMult(cipher_mult0_3_0, cipher_mult0_7_0);
auto cipher_mult2_0_0 = cc->EvalMult(cipher_mult1_0_0, cipher_mult1_2_0);
auto cipher_mult2_1_0 = cc->EvalMult(cipher_mult1_1_0, cipher_mult1_3_0);
auto cipher_mult3_0_0 = cc->EvalMult(cipher_mult2_0_0, cipher_mult2_1_0);

// Tree mult - final product stored in cipher_mult0
auto cipher_mult1_0_1 = cc->EvalMult(cipher_mult0_0_1, cipher_mult0_4_1);
auto cipher_mult1_1_1 = cc->EvalMult(cipher_mult0_1_1, cipher_mult0_5_1);
auto cipher_mult1_2_1 = cc->EvalMult(cipher_mult0_2_1, cipher_mult0_6_1);
auto cipher_mult1_3_1 = cc->EvalMult(cipher_mult0_3_1, cipher_mult0_7_1);
auto cipher_mult2_0_1 = cc->EvalMult(cipher_mult1_0_1, cipher_mult1_2_1);
auto cipher_mult2_1_1 = cc->EvalMult(cipher_mult1_1_1, cipher_mult1_3_1);
auto cipher_mult3_0_1 = cc->EvalMult(cipher_mult2_0_1, cipher_mult2_1_1);

// Tree mult - final product stored in cipher_mult0
auto cipher_mult1_0_2 = cc->EvalMult(cipher_mult0_0_2, cipher_mult0_4_2);
auto cipher_mult1_1_2 = cc->EvalMult(cipher_mult0_1_2, cipher_mult0_5_2);
auto cipher_mult1_2_2 = cc->EvalMult(cipher_mult0_2_2, cipher_mult0_6_2);
auto cipher_mult1_3_2 = cc->EvalMult(cipher_mult0_3_2, cipher_mult0_7_2);
auto cipher_mult2_0_2 = cc->EvalMult(cipher_mult1_0_2, cipher_mult1_2_2);
auto cipher_mult2_1_2 = cc->EvalMult(cipher_mult1_1_2, cipher_mult1_3_2);
auto cipher_mult3_0_2 = cc->EvalMult(cipher_mult2_0_2, cipher_mult2_1_2);

// Tree mult - final product stored in cipher_mult0
auto cipher_mult1_0_3 = cc->EvalMult(cipher_mult0_0_3, cipher_mult0_4_3);
auto cipher_mult1_1_3 = cc->EvalMult(cipher_mult0_1_3, cipher_mult0_5_3);
auto cipher_mult1_2_3 = cc->EvalMult(cipher_mult0_2_3, cipher_mult0_6_3);
auto cipher_mult1_3_3 = cc->EvalMult(cipher_mult0_3_3, cipher_mult0_7_3);
auto cipher_mult2_0_3 = cc->EvalMult(cipher_mult1_0_3, cipher_mult1_2_3);
auto cipher_mult2_1_3 = cc->EvalMult(cipher_mult1_1_3, cipher_mult1_3_3);
auto cipher_mult3_0_3 = cc->EvalMult(cipher_mult2_0_3, cipher_mult2_1_3);

vector<Ciphertext<DCRTPoly>> ciphertextSums;
auto ciphertextSum0 = cc->EvalSum(cipher_mult3_0_0, 32);
ciphertextSums.push_back(ciphertextSum0);
auto ciphertextSum1 = cc->EvalSum(cipher_mult3_0_1, 32);
ciphertextSums.push_back(ciphertextSum1);
auto ciphertextSum2 = cc->EvalSum(cipher_mult3_0_2, 32);
ciphertextSums.push_back(ciphertextSum2);
auto ciphertextSum3 = cc->EvalSum(cipher_mult3_0_3, 32);
ciphertextSums.push_back(ciphertextSum3);


auto ciphertextFinalSum = cc->EvalAddMany(ciphertextSums);

std::vector<int64_t> modifier = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
Plaintext plaintext_mask = cc->MakePackedPlaintext(modifier);
Ciphertext<DCRTPoly> cipher_mask;
cipher_mask = cc->Encrypt(kp8.publicKey, plaintext_mask);

auto ciphertextFinal = cc->EvalMult(cipher_mask, ciphertextFinalSum);



/*
std::vector<int64_t> modifier = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
Plaintext plaintext_modifier = cc->MakePackedPlaintext(modifier);
Ciphertext<DCRTPoly> cipher_modifier;
cipher_modifier = cc->Encrypt(kp8.publicKey, plaintext_modifier);

vector<Ciphertext<DCRTPoly>> partialSums;
partialSums.push_back(ciphertextSum0[0]);
partialSums.push_back(ciphertextSum1[0]);
partialSums.push_back(ciphertextSum2[0]);
partialSums.push_back(ciphertextSum3[0]);

auto aggregateSums = cc->EvalSum(cipher_mult3_0_0, num_buckets);
Ciphertext<DCRTPoly> output = aggregateSums[0];
*/





vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult1;
auto ciphertextPartial01 = cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial01[0]);
auto ciphertextPartial11 = cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial11[0]);
auto ciphertextPartial21 = cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial21[0]);
auto ciphertextPartial31 = cc->MultipartyDecryptMain(kp4.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial31[0]);
auto ciphertextPartial41 = cc->MultipartyDecryptMain(kp5.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial41[0]);
auto ciphertextPartial51 = cc->MultipartyDecryptMain(kp6.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial51[0]);
auto ciphertextPartial61 = cc->MultipartyDecryptMain(kp7.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial61[0]);
auto ciphertextPartial71 = cc->MultipartyDecryptMain(kp8.secretKey, {ciphertextFinal});
partialCiphertextVecMult1.push_back(ciphertextPartial71[0]);


//Decrypting 
vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
auto ciphertextPartial0 = cc->MultipartyDecryptLead(kp1.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial0[0]);
auto ciphertextPartial1 = cc->MultipartyDecryptMain(kp2.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
auto ciphertextPartial2 = cc->MultipartyDecryptMain(kp3.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
auto ciphertextPartial3 = cc->MultipartyDecryptMain(kp4.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial3[0]);
auto ciphertextPartial4 = cc->MultipartyDecryptMain(kp5.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial4[0]);
auto ciphertextPartial5 = cc->MultipartyDecryptMain(kp6.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial5[0]);
auto ciphertextPartial6 = cc->MultipartyDecryptMain(kp7.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial6[0]);
auto ciphertextPartial7 = cc->MultipartyDecryptMain(kp8.secretKey, {cipher_mult3_0_0});
partialCiphertextVecMult.push_back(ciphertextPartial7[0]);

Plaintext plaintextMultipartyMult;

Plaintext plaintextMultipartyMult1;


cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

cc->MultipartyDecryptFusion(partialCiphertextVecMult1, &plaintextMultipartyMult1);

plaintextMultipartyMult->SetLength(plaintext0_0->GetLength());
cout << plaintextMultipartyMult << endl;

plaintextMultipartyMult1->SetLength(plaintext0_0->GetLength());
cout << plaintextMultipartyMult1 << endl;

//Write out
fstream myfile;
std::string f_path = sketch_dir + "tmp.txt";
myfile.open(f_path, ios::out);
myfile << plaintextMultipartyMult1;
myfile.close();
}



std::vector<std::vector<int64_t>> FetchSketches(int hospital_number, std::string sketch_dir){
  static int COLS = 32;
  std::string f_path = sketch_dir+ "/hospital_" + std::to_string(hospital_number) +"_sketches.csv";
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



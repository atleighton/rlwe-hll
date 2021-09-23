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
  SecurityLevel securityLevel = HEStd_128_classic; // TODO ???
  uint32_t depth = ceil(log2(num_hospitals)); 
  //TODO sigma param???

  std::cout << "Calculated depth " << depth << std::endl;

  // Generate the cryptocontext
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          0, plaintextModulus, securityLevel);

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
  std::vector<LPKeyPair<DCRTPoly>> publicKeyContainers;
  for (int i = 0; i < num_hospitals; i++){
    LPKeyPair<DCRTPoly> kp; //TODO make sure it isn't using same keys
    publicKeyContainers.push_back(kp);
  }
  LPKeyPair<DCRTPoly> kp1;
  LPKeyPair<DCRTPoly> kp2;
  LPKeyPair<DCRTPoly> kp3;

  LPKeyPair<DCRTPoly> kpMultiparty;



  ////////////////////////////////////////////////////////////
  // Load sketches from csv
  ////////////////////////////////////////////////////////////

  


  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  std::cout << "Running key generation (used for source data)..." << std::endl;

  // generate the public key for first share
  kp1 = cc->KeyGen();
  // generate the public key for two shares
  kp2 = cc->MultipartyKeyGen(kp1.publicKey);
  // generate the public key for all three secret shares
  kp3 = cc->MultipartyKeyGen(kp2.publicKey);

  if (!kp1.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }
  if (!kp2.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }
  if (!kp3.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<std::vector<int64_t>> sketch_buckets;
  std::cout << "My code" << std::endl;
  sketch_buckets= FetchSketches(1);
  std::vector<int64_t> vectorOfInts1 = sketch_buckets[0];
  std::vector<int64_t> vectorOfInts2 = sketch_buckets[1];
  std::vector<int64_t> vectorOfInts3 = sketch_buckets[2];

  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  Ciphertext<DCRTPoly> ciphertext1;
  Ciphertext<DCRTPoly> ciphertext2;
  Ciphertext<DCRTPoly> ciphertext3;

  ciphertext1 = cc->Encrypt(kp3.publicKey, plaintext1);
  ciphertext2 = cc->Encrypt(kp3.publicKey, plaintext2);
  ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Ciphertext<DCRTPoly> ciphertextAdd12;
  Ciphertext<DCRTPoly> ciphertextAdd123;

  ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data with Multiparty
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAddNew1;
  Plaintext plaintextAddNew2;
  Plaintext plaintextAddNew3;

  DCRTPoly partialPlaintext1;
  DCRTPoly partialPlaintext2;
  DCRTPoly partialPlaintext3;

  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  // partial decryption by first party
  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});

  // partial decryption by second party
  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  // partial decryption by third party
  auto ciphertextPartial3 =
      cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextAdd123});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);
  partialCiphertextVec.push_back(ciphertextPartial3[0]);

  // partial decryptions are combined together
  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

  cout << "\n Original Plaintext: \n" << endl;
  cout << plaintext1 << endl;
  cout << plaintext2 << endl;
  cout << plaintext3 << endl;

  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  cout << "\n Resulting Fused Plaintext adding 3 ciphertexts: \n" << endl;
  cout << plaintextMultipartyNew << endl;

  cout << "\n";


}



std::vector<std::vector<int64_t>> FetchSketches(int hospital_number){
  static int COLS = 32;
  std::string f_path = std::__fs::filesystem::current_path().parent_path().string() + "/sim_sketches/hospital_" + std::to_string(hospital_number) +"_sketches.csv";
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
  std::cout << "Data for hospital " << std::to_string(hospital_number) << std::endl;
  for (int i =0; i < 4; i++){
    for (int j=0; j < 32; j++){
      std::cout << std::to_string(sketch_buckets[i][j]) << " ";
    }
    std::cout << std::endl;
  }

  return sketch_buckets;
}



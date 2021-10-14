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

using namespace std;
using namespace lbcrypto;

void RunBFVrns();

int main(int argc, char *argv[]) {

  std::cout << "\n=================RUNNING FOR BFVrns====================="
            << std::endl;

  RunBFVrns();

  return 0;
}

void RunBFVrns() {
  int plaintextModulus = 65537; 
  double sigma = 3.2;
  uint32_t depth = 2; // Multiplicative depth
  SecurityLevel securityLevel = HEStd_128_classic;

  EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus));

  usint batchSize = 1024;
  encodingParams->SetBatchSize(batchSize);

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, securityLevel, sigma, 0, depth, 0, OPTIMIZED, 2, 30, 60);

  uint32_t m = cc->GetCyclotomicOrder();
  PackedEncoding::SetParams(m, encodingParams);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(MULTIPARTY);

  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////

  // Output the generated parameters
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

  std::cout << "multiplicative depth = "
            << depth << std::endl;

  // Initialize Public Key Containers for three parties A, B, C
  LPKeyPair<DCRTPoly> kp1;
  LPKeyPair<DCRTPoly> kp2;
  LPKeyPair<DCRTPoly> kp3;

  //LPKeyPair<DCRTPoly> kpMultiparty;

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

kp1 = cc->KeyGen();

// Generate evalmult key part for lead
auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

// Generate evalsum key part for lead
cc->EvalSumKeyGen(kp1.secretKey);
auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(     
    cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));   

// Joint public key for (s_1 + s_2)
kp2 = cc->MultipartyKeyGen(kp1.publicKey);

// Generate evalmult key part for party 2
auto evalMultKey2 =
    cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

// Joint evaluation multiplication key for (s_1 + s_2)
auto evalMult_up_to_2 = 
    cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
// Generate evalsum key part for part 2
cc->EvalSumKeyGen(kp2.secretKey);
auto evalSumKeys2 = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                           kp2.publicKey->GetKeyTag());

// Joint evaluation summation key for (s_1 + s_2)
auto evalSumKeysJoin_to_2 = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeys2,
                                                    kp2.publicKey->GetKeyTag());
// Joint public key for (s_1 + s_2 + s_3)
kp3 = cc->MultipartyKeyGen(kp2.publicKey);

// Generate evalmult key part for party 3
auto evalMultKey3 =
    cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMult_up_to_2);


// Joint evaluation multiplication key for (s_1 + s_2 + s_3)
auto evalMult_up_to_3 = 
    cc->MultiAddEvalKeys(evalMult_up_to_2, evalMultKey3,
                         kp3.publicKey->GetKeyTag());

// Generate evalsum key part for part 3
cc->EvalSumKeyGen(kp3.secretKey);
auto evalSumKeys3 = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysJoin_to_2,
                                           kp3.publicKey->GetKeyTag());

// Joint evaluation summation key for (s_1 + s_2 + s_3)
auto evalSumKeysJoin_to_3 = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_2,
    evalSumKeys3, kp3.publicKey->GetKeyTag());
cc->InsertEvalSumKey(evalSumKeysJoin_to_3);



// Joint key (s_1 + s_2 + s_3) is transformed into s_1*(s_1 + s_2 + s_3)
auto evalMultJoint1 = cc->MultiMultEvalKey(evalMult_up_to_3, kp1.secretKey,
                                           kp3.publicKey->GetKeyTag());

// Joint key (s_1 + s_2 + s_3) is transformed into s_2*(s_1 + s_2 + s_3)
auto evalMultJoint2 = cc->MultiMultEvalKey(evalMult_up_to_3, kp2.secretKey,
                                           kp3.publicKey->GetKeyTag());

// Joint key (s_1 + s_2 + s_3) is transformed into s_3*(s_1 + s_2 + s_3)
auto evalMultJoint3 = cc->MultiMultEvalKey(evalMult_up_to_3, kp3.secretKey,
                                           kp3.publicKey->GetKeyTag());
// Final evaluation multiplication key for (s_1 + s_2 + s_3) * (s_1 + s_2 + s_3)
auto evalMultPartial2 = cc->MultiAddEvalMultKeys(evalMultJoint1, evalMultJoint2,
                                             kp3.publicKey->GetKeyTag());
auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultPartial2, evalMultJoint3,
                                          kp3.publicKey->GetKeyTag());
cc->InsertEvalMultKey({evalMultFinal});

  std::cout << "Keys generated!" << std::endl;

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  Ciphertext<DCRTPoly> ciphertext1;
  Ciphertext<DCRTPoly> ciphertext2;
  Ciphertext<DCRTPoly> ciphertext3;
  std::vector<Ciphertext<DCRTPoly>> Ciphertexts;

  ciphertext1 = cc->Encrypt(kp3.publicKey, plaintext1);
  ciphertext2 = cc->Encrypt(kp3.publicKey, plaintext2);
  ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);

  std::cout << "Encrypted!" << std::endl;

  ////////////////////////////////////////////////////////////
  // Homomorphic Operations
  ////////////////////////////////////////////////////////////

  Ciphertext<DCRTPoly> ciphertextAdd12;
  Ciphertext<DCRTPoly> ciphertextAdd123;

  ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

  auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext3);
  auto ciphertextEvalSum = cc->EvalSum(ciphertext3, batchSize);

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

  // Distributed decryption

  // partial decryption by party A
  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});

  // partial decryption by party B
  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  // partial decryption by party C
  auto ciphertextPartial3 =
      cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextAdd123});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);
  partialCiphertextVec.push_back(ciphertextPartial3[0]);

  // Three partial decryptions are combined
  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

  cout << "\n Original Plaintext: \n" << endl;
  cout << plaintext1 << endl;
  cout << plaintext2 << endl;
  cout << plaintext3 << endl;

  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  cout << "\n Resulting Fused Plaintext: \n" << endl;
  cout << plaintextMultipartyNew << endl;

  cout << "\n";

  Plaintext plaintextMultipartyMult;

  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextMult});

  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextMult});

  ciphertextPartial3 =
      cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextMult});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial3[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecMult,
                              &plaintextMultipartyMult);

  plaintextMultipartyMult->SetLength(plaintext1->GetLength());

  cout << "\n Resulting Fused Plaintext after Multiplication of plaintexts 1 "
          "and 3: \n"
       << endl;
  cout << plaintextMultipartyMult << endl;

  cout << "\n";

  Plaintext plaintextMultipartyEvalSum;

  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextEvalSum});

  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextEvalSum});

  ciphertextPartial3 =
      cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextEvalSum});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
  partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
  partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);
  partialCiphertextVecEvalSum.push_back(ciphertextPartial3[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum,
                              &plaintextMultipartyEvalSum);

  plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

  cout << "\n Fused result after summation of ciphertext 3: \n" << endl;
  cout << plaintextMultipartyEvalSum << endl;
}


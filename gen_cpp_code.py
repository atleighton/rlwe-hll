#!/usr/bin/env python3
import math
from optparse import OptionParser
import os


def readCL():
	parser = OptionParser()
	parser.add_option("-z", "--num_hospitals", default = 8)
	parser.add_option("-b", "--num_buckets", default = 4)
	(options, args) = parser.parse_args()

	return int(options.num_hospitals), int(options.num_buckets)


def tree_mult(f, num_parties, num_buckets):
	f.write("\n// Tree mult - final product stored in cipher_mult_{depth}_0_{bucket}\n")
	f.write("\n// Intermediate format cipher_mult_{round#}_{node of tree#}_{bucket#}")
	for j in range(num_buckets):
		round_num = 1
		num_pairs = num_parties
		f.write("\n// Tree mult - final product stored in cipher_mult0\n")
		while num_pairs > 1:
			iters_todo = int(num_pairs - (next_power_of_2(num_pairs)//2))
			if round_num == 1 and num_parties != next_power_of_2(num_parties):
				for i in range(iters_todo, num_parties-iters_todo):
					f.write("Ciphertext<DCRTPoly> cipher_mult1_{0}_{1} = cipher_mult0_{0}_{1} ;\n".format(i, j))
			for i in range(iters_todo):
				f.write("auto cipher_mult{3}_{0}_{4} = cc->EvalMult(cipher_mult{2}_{0}_{4}, cipher_mult{2}_{1}_{4});\n".format(i, next_power_of_2(num_pairs)//2 + i, round_num -1, round_num, j))
			num_pairs = next_power_of_2(num_pairs) // 2
			round_num += 1
	return


def key_gen(f, num_parties):
	#initialize keys 
	f.write("\n//initialize public key container for {0} parties \n".format(num_parties))
	for party in range(num_parties):
		f.write("LPKeyPair<DCRTPoly> kp{0};\n".format(party+1));
	#generate sum and mult keys
	#lead party
	f.write("kp1 = cc->KeyGen();\n")
	# mult key
	f.write("\n// Generate mult key part for lead\n")
	f.write("auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);\n")
	#sum key
	f.write("\n// Generate evalsum key part for lead\n")
	f.write("cc->EvalSumKeyGen(kp1.secretKey);\n")
	f.write("auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));\n")
	# party 2 from lead
	f.write("kp2 = cc->MultipartyKeyGen(kp1.publicKey);\n")
	f.write("auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);\n")
	f.write("auto evalMult_up_to_2 = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());\n")
	f.write("cc->EvalSumKeyGen(kp2.secretKey); auto evalSumKeys2 = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,kp2.publicKey->GetKeyTag());\n")
	f.write("auto evalSumKeysJoin_to_2 = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeys2, kp2.publicKey->GetKeyTag());\n")
	#non-lead parties
	for party in range(2, num_parties):
		p = party+1
		#gen keys
		f.write("\n//gen keys party {}\n".format(p))
		f.write("kp{0} = cc->MultipartyKeyGen(kp{1}.publicKey);\n".format(p, p-1))
		# gen mult keys
		f.write("\n// Generate evalmult key part for party {0}\n".format(p))
		f.write("auto evalMultKey{0} = cc->MultiKeySwitchGen(kp{1}.secretKey, kp{2}.secretKey, evalMult_up_to_{3});\n".format(p,p,p,p-1))
		f.write("auto evalMult_up_to_{0} = cc->MultiAddEvalKeys(evalMult_up_to_{1}, evalMultKey{2}, kp{3}.publicKey->GetKeyTag());\n".format(p, p-1, p, p))
		# sum keys
		f.write("\n// gen eval sum keys\n")
		f.write("cc->EvalSumKeyGen(kp{0}.secretKey);\n".format(p))
		f.write("auto evalSumKeys{0} = cc->MultiEvalSumKeyGen(kp{1}.secretKey, evalSumKeysJoin_to_{2}, kp{3}.publicKey->GetKeyTag());\n".format(p,p,p-1,p))
		f.write("auto evalSumKeysJoin_to_{0} = cc->MultiAddEvalSumKeys(evalSumKeysJoin_to_{1}, evalSumKeys{2}, kp{3}.publicKey->GetKeyTag());\n".format(p, p-1, p, p))
	# joint multiplication keys
	for party in range(num_parties):
		p = party+1
		f.write("auto evalMultJoint{0} = cc->MultiMultEvalKey(evalMult_up_to_{1}, kp{2}.secretKey, kp{3}.publicKey->GetKeyTag());\n".format(p, num_parties, p, num_parties))
		if p == 2:
			f.write("auto evalMultPartial{0} = cc->MultiAddEvalMultKeys(evalMultJoint{1}, evalMultJoint{2}, kp{3}.publicKey->GetKeyTag());\n".format(p, p-1, p, num_parties))
		if p > 2:
			f.write("auto evalMultPartial{0} = cc->MultiAddEvalMultKeys(evalMultPartial{1}, evalMultJoint{2}, kp{3}.publicKey->GetKeyTag());\n".format(p, p-1, p, num_parties))
	# final mult key
	f.write("\n// insert final mult key\n")
	f.write("cc->InsertEvalMultKey({evalMultPartial"+str(num_parties)+"});\n")
	#final sum key
	f.write("\n// insert final sum key \n")
	f.write("cc->InsertEvalSumKey(evalSumKeysJoin_to_{0});\n".format(num_parties))
	#keygen done
	f.write('std::cout << "Keys generated!" << std::endl;\n')
	return

def encrypt(f, num_parties, num_buckets):
	#cipher_mult{hospital num}_{bucket num}
	for j in range(num_buckets):
		f.write("vector<Ciphertext<DCRTPoly>> bucket_{0}_ciphertexts;\n".format(j))
		for i in range(num_parties):
			f.write("\nPlaintext plaintext"+str(i)+"_"+ str(j)+" = cc->MakePackedPlaintext(hospital_sketches["+str(i)+"]["+str(j)+"]);\n")
			f.write("Ciphertext<DCRTPoly> cipher_mult0_{0}_{2} = cc->Encrypt(kp{1}.publicKey, plaintext{0}_{2});\n".format(i, num_parties, j))
	return


def tree_mult_built_in(f, num_parties, num_buckets):
	for j in range(num_buckets):
		f.write("auto bucket_{0}_multiplied = cc->EvalMultMany(bucket_{0}_ciphertexts);\n".format(j))
	return

def decrypt(f, num_parties):
	num_rounds = int(math.log2(next_power_of_2(num_parties)))
	f.write("\n//Decrypting \n")
	f.write("vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;\n")
	f.write("auto ciphertextPartial0 = cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextFinal});\n")
	f.write("partialCiphertextVecMult.push_back(ciphertextPartial0[0]);\n")
	for i in range(1,num_parties):
		f.write("auto ciphertextPartial"+str(i)+" = cc->MultipartyDecryptMain(kp"+str(i+1)+".secretKey, {ciphertextFinal});\n")
		f.write("partialCiphertextVecMult.push_back(ciphertextPartial{0}[0]);\n".format(i))
	f.write("\nPlaintext plaintextMultipartyMult;\n")
	f.write("\ncc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);\n")
	f.write("\nplaintextMultipartyMult->SetLength(plaintext0_0->GetLength());\n")
	#print
	f.write("cout << plaintextMultipartyMult << endl;\n")
	return

def merge_mults(f, num_parties, num_buckets):
	#SummedCiphertext{sumation_number}_{bucket}
	num_rounds = int(math.log2(next_power_of_2(num_parties)))
	f.write("\n// Computing ciphertext sumation\n")
	f.write("std::vector<Ciphertext<DCRTPoly>> ciphertextSums;\n")
	for j in range(num_buckets):
		f.write("ciphertextSums.push_back(cc->EvalSum(cipher_mult{0}_0_{1}, 32));\n".format(num_rounds, j))
	f.write("auto ciphertextFinalSum = cc->EvalAddMany(ciphertextSums);\n")
	return

def mask_mults(f, num_parties):
	f.write("//this and a few other operations can and should be verified in practice else a malicious party can choose not to preform the step\n")
	f.write("std::vector<int64_t> modifier = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};\n")
	f.write("Plaintext plaintext_mask = cc->MakePackedPlaintext(modifier);\n")
	f.write("Ciphertext<DCRTPoly> cipher_mask;\n")
	f.write("cipher_mask = cc->Encrypt(kp{0}.publicKey, plaintext_mask);\n".format(num_parties))
	f.write("auto ciphertextFinal = cc->EvalMult(cipher_mask, ciphertextFinalSum);\n")
	return



def next_power_of_2(x):  
    return 1 if x == 0 else 2**(x - 1).bit_length()


def pasteCPPCode(f, num_parties, num_buckets):
	f.write(''' // @file  threshold-fhe.cpp - Examples of threshold FHE for BGVrns, BFVrns, and
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
	''')
	f.write('''#include "palisade.h"
#include <chrono>
#include <iostream>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept> // std::runtime_error

using namespace std;
using namespace lbcrypto;''')
	f.write('''
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


  std::cout << "=================RUNNING FOR HLL Sketches=====================" << std::endl;

  RunHLLSketch(hospital_sketches, num_hospitals, num_buckets, sketch_dir);

  return 0;
}
''')
	f.write('''void RunHLLSketch(std::vector<std::vector<std::vector<int64_t>>> hospital_sketches, int num_hospitals, int num_buckets, std::string sketch_dir) {
  uint32_t plaintextModulus = 65537; //TODO ???
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic; // TODO ???
  uint32_t depth = ceil(log2(num_hospitals))+1; 
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
  TimeVar t;
  double processingTime(0.0);

''')
	f.write("TIC(t);\n")
	key_gen(f, num_parties)
	f.write("processingTime = TOC(t);\n")
	f.write('std::cout << "Key generation time: " << processingTime << "ms" << std::endl;\n')

	f.write("TIC(t);\n")
	encrypt(f, num_parties, num_buckets)
	f.write("processingTime = TOC(t);\n")
	f.write('std::cout << "Encryption time: " << processingTime << "ms" << std::endl;\n')

	f.write("TIC(t);\n")
	tree_mult(f, num_parties, num_buckets)
	f.write("processingTime = TOC(t);\n")
	f.write('std::cout << "Multiplication time: " << processingTime << "ms" << std::endl;\n')

	f.write("TIC(t);\n")
	merge_mults(f, num_parties, num_buckets)
	f.write("processingTime = TOC(t);\n")
	f.write('std::cout << "Summation time: " << processingTime << "ms" << std::endl;\n')

	mask_mults(f, num_parties)

	f.write("TIC(t);\n")
	decrypt(f, num_parties)
	f.write("processingTime = TOC(t);\n")
	f.write('std::cout << "Decryption time: " << processingTime << "ms" << std::endl;\n')
	f.write('''//Write out
fstream myfile;
std::string f_path = sketch_dir + "tmp.txt";
myfile.open(f_path, ios::out);
myfile << plaintextMultipartyMult;
myfile.close();
}
''')
	f.write('''
std::vector<std::vector<int64_t>> FetchSketches(int hospital_number, std::string sketch_dir){
  static int COLS = 32;
  std::string f_path = sketch_dir+ "/hospital_" + std::to_string(hospital_number) +"_sketches.csv";
  std::cout << "=========== Looking for hospital sketch at " + f_path+
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
}''')
	return






if __name__ == "__main__":
	num_hospitals, num_buckets = readCL()
	cpp_file= "{}/cpp_metacode.cpp".format(os.getcwd())
	with open(cpp_file, "w") as f:
		pasteCPPCode(f, num_hospitals, num_buckets)
		#key_gen(f, num_parties)
		#encrypt(f, num_parties, num_buckets)
		#tree_mult(f, num_parties,num_hospitals)
		#decrypt(f, num_parties)








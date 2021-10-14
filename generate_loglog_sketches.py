#!/usr/bin/env python3
from optparse import OptionParser
import csv
import math
import os
import numpy as np
import hashlib
import binascii

def readCL():
	parser = OptionParser()
	parser.add_option("-d", "--input_dir", default = "{0}/sim_data".format(os.getcwd()))
	parser.add_option("-o", "--output_dir", default = "{0}/sim_sketches".format(os.getcwd()))
	parser.add_option("-n", "--num_patients", default = 1000)
	parser.add_option("-k", "--num_conditions", default = 10)
	parser.add_option("-z", "--num_hospitals", default = 3)
	parser.add_option("-b", "--num_buckets", default = 4)
	(options, args) = parser.parse_args()

	return options.input_dir, options.output_dir, int(options.num_patients), int(options.num_conditions), int(options.num_hospitals), int(options.num_buckets)

def readCSV(f):
	with open(f, "r") as csvfile:
		reader = csv.reader(csvfile)
		row1 = next(reader)
		for row in reader:
			row_dict = {}
			for i in range(len(row1)):
				row_dict[row1[i]] = row[i]
			yield row_dict

def load_data(input_dir, num_patients, num_conditions, num_hospitals):
	hospitals = []
	for i in range(num_hospitals):
		hospital_num = i+1
		fpath = "{0}/hospital_{1}_data.csv".format(input_dir, hospital_num)
		hospitals.append(np.genfromtxt(fpath, delimiter = ','))
	return hospitals

def log_log(hospital_path, num_buckets):
	hospital_numerical_sketches = np.zeros(num_buckets)
	for row in readCSV(hospital_path):
		hex_digest = hashlib.sha1(row["SSN"]).hexdigest()
		binary_hash = bin(int(hex_digest, 16))[2:].zfill(160)
		bucket = int(binary_hash[:64], 2)%num_buckets
		leading_zeros = 0
		for i in binary_hash[64:128]:
			if i == "0":
				leading_zeros += 1
			else:
				break
		if hospital_numerical_sketches[bucket] < leading_zeros:
			hospital_numerical_sketches[bucket] = leading_zeros
	return hospital_numerical_sketches

def write_unary_sketches(hospital_sketch_path, hospital_numerical_sketches):
	'''
	writes a csv file for each hospital
	row# = bucket (length 32 unary representing max # leading zeros)
	'''
	with open(hospital_sketch_path, "w") as csvfile:
		writer = csv.writer(csvfile)
		for bucket in hospital_numerical_sketches:
			val = int(bucket)
			unary_bucket = ["0"]*val + ["1"] * (32-val)
			writer.writerow(unary_bucket)
	return



def gen_write_sketches(input_dir, output_dir, num_patients, num_hospitals, num_conditions, num_buckets):
	for i in range(num_hospitals):
		hospital_num = i+1
		hospital_input_path = "{0}/hospital_{1}_data.csv".format(input_dir, hospital_num)
		hospital_sketch_path = "{0}/hospital_{1}_sketches.csv".format(output_dir, hospital_num)
		hospital_numerical_sketches = log_log(hospital_input_path, num_buckets)
		write_unary_sketches(hospital_sketch_path, hospital_numerical_sketches)
	return

def sample_query():
	'''
	TODO: fix this up - should return 
	'''
	return

def main():
	input_dir, output_dir, num_patients, num_conditions, num_hospitals, num_buckets = readCL()
	if not os.path.isdir(output_dir):
		os.mkdir(output_dir)
	gen_write_sketches(input_dir, output_dir, num_patients, num_hospitals, num_conditions, num_buckets)
	return




if __name__ == "__main__":
	main()
#!/usr/bin/env python3

import math
from optparse import OptionParser
from scipy.special import gamma
import os


def readCL():
	parser = OptionParser()
	parser.add_option("-i", "--input_path", default = "{0}/sim_sketches/".format(os.getcwd()))
	parser.add_option("-b", "--num_buckets", default = 4)
	(options, args) = parser.parse_args()

	return int(options.num_buckets), options.input_path

def read_input(input_path):
	f = input_path + "tmp.txt"
	with open(f, "r") as plaintext_f:
		contents = plaintext_f.readlines()
		sum_1s = [int(s) for s in contents[0].split() if s.isdigit()][0]
	print (sum_1s)
	N = 33.0*num_buckets -sum_1s
	return N

def approximateCardinality(num_buckets, input_path):
	N = read_input(input_path)
	print(N)
	T_m = gamma(-1.0/num_buckets + 1)/(-1.0/num_buckets)
	print(T_m)
	frac = ((1 - (2**(1.0/num_buckets)))/math.log(2))
	print(frac)
	a_m = (T_m * frac)**(-num_buckets)
	print (a_m)
	return a_m * num_buckets * 2**(N/num_buckets)


if __name__ == "__main__":
	num_buckets, input_path = readCL()
	approximation = approximateCardinality(num_buckets, input_path)
	print("Final cardinality estimation:")
	print(approximation)
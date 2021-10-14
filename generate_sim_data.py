#!/usr/bin/env python3
from optparse import OptionParser
import csv
import math
import random
import os
import numpy as np


def readCL():
	parser = OptionParser()
	parser.add_option("-d", "--out_dir", default = "{0}/sim_data/".format(os.getcwd()))
	parser.add_option("-n", "--num_patients", default = 1000)
	parser.add_option("-k", "--num_conditions", default = 10)
	parser.add_option("-z", "--num_hospitals", default = 3)
	(options, args) = parser.parse_args()

	return options.out_dir, int(options.num_patients), int(options.num_conditions), int(options.num_hospitals)

def random_ssn():
	rand_num = random.randrange(1000000,9999999)
	rand_str = str(rand_num%1000000).zfill(6)
	blank1 = rand_str[:2]
	blank2 = rand_str[2:]
	return "000-{0}-{1}".format(blank1, blank2)


def write_sim_data_csvs(out_dir, num_patients, num_conditions, num_hospitals, p = .5):
	if not os.path.isdir(out_dir):
		os.mkdir(out_dir)
	for i in range(num_hospitals):
		f = "{0}/hospital_{1}_data.csv".format(out_dir, str(i+1))
		with open(f, "w") as csvfile:
			writer = csv.writer(csvfile)
			row1 = ["SSN"]
			for i in range(num_conditions):
				row1.append("condition_{0}".format(str(i+1)))
			writer.writerow(row1)
			for i in range(num_patients):
				row = [random_ssn()] + list(np.random.choice([0, 1], size=(num_conditions,), p=[p, 1-p]))
				writer.writerow(row)
	return


def main():
	out_dir, num_patients, num_conditions, num_hospitals = readCL()
	write_sim_data_csvs(out_dir, num_patients, num_conditions, num_hospitals)
	return

if __name__ == "__main__":
	main()

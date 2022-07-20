from argparse import ArgumentParser
from checksum import hash_algo_map, DEFAULT_ALGO, DEFAULT_BLOCK_SIZE, \
	compare_checksum, checksum_walk
from os.path import isfile, isdir
from error_handler import cascade_error_handler

def parse_args():
	arg_parser = ArgumentParser(description='Compare checksum hashes for copied files:')
	input_data_group = arg_parser.add_mutually_exclusive_group(required=True)
	input_data_group.add_argument('-f', '--file', nargs=2, help='specifies to compare a single set of files')
	input_data_group.add_argument('-d', '--directory', nargs=2, help='specifies to recursively compare two directories')
	arg_parser.add_argument('-algorithm', type=str.lower, choices=hash_algo_map.keys(), \
		default=DEFAULT_ALGO, help='specifies the desired hash algorithm')
	arg_parser.add_argument('-v', '--verbose', action='store_true', help='enables verbose logging mode')
	arg_parser.add_argument('-b', '--block-size', dest='block_size', type=int, nargs='?', const=DEFAULT_BLOCK_SIZE, \
			default=DEFAULT_BLOCK_SIZE, help='specifies the buffer size in bytes for file read operations')
	return arg_parser.parse_args()

def main():
	argv = parse_args()

	# print details for verbose option
	if argv.verbose:

		if (argv.file != None):
			print('source file : ' + argv.file[0])
			print('dest file   : ' + argv.file[1])
		elif(argv.directory != None):
			print('source directory : ' + argv.directory[0])
			print('dest directory   : ' + argv.directory[1])
		else:
			print('ERROR: No input data specified.')
			exit()
		
		print('algorithm   : ' + argv.algorithm)
		print('block size  : ' + str(argv.block_size))

	# check args for file and directory options
	if (argv.file != None):
		file_error = False
		if not isfile(argv.file[0]):
			print("ERROR: provided argument is not a file - " + argv.file[0])
			file_error = True
		
		if not isfile(argv.file[1]):
			print("ERROR: provided argument is not a file - " + argv.file[1])
			file_error = True

		if file_error:
			exit()
		
		if compare_checksum(argv.file[0], argv.file[1], argv.algorithm, argv.block_size):
			print('-- checksum passed --')
		else:
			print('-- checksum failed --') 

	elif(argv.directory != None):
		error_list = [
			(isdir(argv.directory[0]), "ERROR: provided argument is not a directory - " + argv.directory[0]),
			(isdir(argv.directory[1]), "ERROR: provided argument is not a directory - " + argv.directory[1])
		]

		if cascade_error_handler(error_list):
			exit()
		
		checksum_walk(argv.directory[0], argv.directory[1], argv.algorithm, argv.block_size)

	else:
		print('ERROR: No input data specified.')
		exit()

if __name__ == "__main__":
	main()






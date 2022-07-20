from hashlib import sha1, sha224, sha256, sha384, sha512
from itertools import zip_longest
from os.path import join
from typing import Tuple
from custom_lib import sorted_walk, GeneratorBrake


SHA1 = 'sha1'
SHA224 = 'sha224'
SHA256 = 'sha256'
SHA384 = 'sha384'
SHA512 = 'sha512'

hash_algo_map = {
	SHA1   : sha1,
	SHA224 : sha224,
	SHA256 : sha256,
	SHA384 : sha384,
	SHA512 : sha512,
}

DEFAULT_ALGO = SHA256
DEFAULT_BLOCK_SIZE = 4096

def hash_file(file_path : str, hash_algo : str = DEFAULT_ALGO, 
	block_size_bytes : int = DEFAULT_BLOCK_SIZE) -> str:
	"""Takes the input file and generates a cryptographic hash using the specified cryptographic hash algorithm.

	Args:
		file_path (str): Specifies the path to the input file.
		hash_algo (str, optional): Specifies the cryptographic function to use.
			Options are [SHA1, SHA224, SHA256, SHA384, SHA512]. Defaults to DEFAULT_ALGO.
		block_size_bytes (int, optional): Specifies the buffer size for file read.
			Defaults to DEFAULT_BLOCK_SIZE.
		
	Returns:
		str: Returns a hexadecimal cryptographic digest of the input file.
	"""
	if hash_algo.lower() in hash_algo_map.keys():
		hash_function = hash_algo_map[hash_algo.lower()]
	else:
		hash_function = hash_algo_map[DEFAULT_ALGO]
	
	hash = hash_function()
	with open(file_path, 'rb') as input_file:
		block = input_file.read(block_size_bytes)
		while block:
			hash.update(block)
			block = input_file.read(block_size_bytes)

	return hash.hexdigest()

def compare_checksum(file_1 : str, file_2 : str, hash_algo :str= DEFAULT_ALGO, 
	block_size_bytes : int = DEFAULT_BLOCK_SIZE) -> bool:
	"""Performs a checksum comparison for two input files, using the specified cryptographic hash algorithm.

	Args:
		file_1 (str): Specifies the path to the first input file.
		file_2 (str): Specifies the path to the second input file.
		hash_algo (str, optional): Specifies the cryptographic hash algorithm to use.
			Options are [SHA1, SHA224, SHA256, SHA384, SHA512]. Defaults to DEFAULT_ALGO.
		block_size_bytes (int, optional): Specifies the buffer size for file read.
			Defaults to DEFAULT_BLOCK_SIZE.

	Returns:
		bool: Returns true if the file hashes are equivalent. Otherwise, returns false.
	"""
	hash_1 = hash_file(file_1, hash_algo, block_size_bytes)
	hash_2 = hash_file(file_2, hash_algo, block_size_bytes)
	return compare_hash(hash_1, hash_2)

def compare_expected_checksum(file_path : str, expected_checksum : str, hash_algo :str= DEFAULT_ALGO, 
	block_size_bytes : int = DEFAULT_BLOCK_SIZE) -> bool:
	"""Performs an expected checksum comparison of an input file, using the specified cryptographic hash algorithm.

	Args:
		file_path (str): Specifies the path to the input file.
		expected_checksum (str): Specifies the expected checksum value in hexadecimal.
		hash_algo (str, optional): Specifies the cryptographic hash algorithm to use.
			Options are [SHA1, SHA224, SHA256, SHA384, SHA512]. Defaults to DEFAULT_ALGO.
		block_size_bytes (int, optional): Specifies the buffer size for file read.
			Defaults to DEFAULT_BLOCK_SIZE.

	Returns:
		bool: Returns true if the file hashes are equivalent. Otherwise, returns false.
	"""
	calculated_checksum = hash_file(file_path, hash_algo, block_size_bytes)
	return compare_hash(calculated_checksum, expected_checksum)

def compare_hash(hash_1 : str, hash_2 : str) -> bool:
	"""Checks if the two input hashes are equivalent.

	Args:
		hash_1 (str): Specifies the first file hash in hexadecimal.
		hash_2 (str): Specifies the second file hash in hexadecimal.

	Returns:
		bool: Returns true if the hashes are equivalent. Otherwise, returns false.
	"""
	ret_val = False
	if (hash_1 == hash_2):
		ret_val = True
		
	return ret_val

def hash_walk(directory : str, hash_algo : str = DEFAULT_ALGO, 
	block_size_bytes : int = DEFAULT_BLOCK_SIZE) -> Tuple[str, str, int]:
	"""Recursively calculates cryptographic hashes for files in the input directory.

	Args:
		directory (str): Specifies the directory.
		hash_algo (str, optional): Specifies the cryptographic hash algorithm to use.
			Options are [SHA1, SHA224, SHA256, SHA384, SHA512]. Defaults to DEFAULT_ALGO.
		block_size_bytes (int, optional): Specifies the buffer size for file read.
			 Defaults to DEFAULT_BLOCK_SIZE.

	Yields:
		Iterator[Tuple[str, str]]: Yeilds a tuple of a file path and the calculated hash.
	"""
	for root, dirs, files, directory_level in sorted_walk(directory):
		for name in files:
			file_path = join(root, name)
			file_checksum = hash_file(file_path, hash_algo, block_size_bytes)
			yield (file_path, file_checksum, directory_level)

def checksum_walk(directory_1 : str, directory_2 : str, hash_algo : str = DEFAULT_ALGO, 
	block_size_bytes : int = DEFAULT_BLOCK_SIZE):
	"""Recursively compares cryptographic checksums for the two input directories using \
		the input hash algorithm.

	Args:
		directory_1 (str): Specifies the first directory.
		directory_2 (str): Specifies the second directory.
		hash_algo (str, optional): Specifies the cryptographic hash algorithm to use.
			Options are [SHA1, SHA224, SHA256, SHA384, SHA512]. Defaults to DEFAULT_ALGO.
		block_size_bytes (int, optional): Specifies the buffer size for file read.
			Defaults to DEFAULT_BLOCK_SIZE.
	"""
	gbrake_1 = GeneratorBrake(hash_walk(directory_1, hash_algo, block_size_bytes))
	gbrake_2 = GeneratorBrake(hash_walk(directory_2, hash_algo, block_size_bytes))
	iter_1, iter_2 = gbrake_1.iter(), gbrake_2.iter()
	
	for val_1, val_2 in zip_longest(iter_1, iter_2):
		gbrake_1.start(), gbrake_2.start()
		
		#if (val_1 is None) and (val_2 is None):
		#	break
		if val_1 is None:
			print("  + " + val_2[0])
		elif val_2 is None:
			print("  - " + val_1[0])
		else:
			rel_1 = val_1[0][len(directory_1):] 
			rel_2 = val_2[0][len(directory_2):]

			if rel_1 == rel_2:
				if val_1[1] != val_2[1]:
					print("___ checksum failed  :  " + val_1[0] + ", " + val_2[0])
			elif (rel_1 > rel_2) and (val_1[2] <= val_2[2]):
				print("  + " + val_2[0])
				gbrake_1.stop(val_1)
			else:
				print("  - " + val_1[0])
				gbrake_2.stop(val_2)








	



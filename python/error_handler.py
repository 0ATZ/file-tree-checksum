from typing import List, Tuple

# TODO - write function for error logging

def cascade_error_handler(status_list : List[Tuple[bool, str]]):
	error_detected = False
	for status, message in status_list:
		if not status:
			print(message)
			error_detected = True
	return error_detected
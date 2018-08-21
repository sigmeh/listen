#!/usr/bin/env python
'''
	bashcom.py

A simple wrapper module for the subprocess Popen method
which I'm tired of writing out.  

Usage:
	>>> from bashcom import bashcom as bc
	>>> bc('pwd')
	>>> /Users/CountChocula/victims

The shell can be set to True with an optional kwarg shell=True
Otherwise bashcom assumes shell=False and splits the given command into a list

Ouput (stdout) is returned (as a newline-split list) 
unless the command results in an error, 
in which case stderr is returned. 

The script can also be run directly, which is mostly useless 
for anything other than testing. 
	
	$ python bashcom.py ls

'''
from subprocess import Popen, PIPE, STDOUT
import sys	
	
def bashcom(cmd, shell=False):
	out, err = Popen(cmd if shell else cmd.split(' '), stdout=PIPE, stderr=STDOUT, shell=shell).communicate()
	return err if err else out
	

def main():
	args = sys.argv[1:]
	shell = False if args[-1] != 'shell=True' else True and args.pop()
	print bashcom( ' '.join(args), shell=shell ) if args else 'Provide commands.'

if __name__ == '__main__':
	main()

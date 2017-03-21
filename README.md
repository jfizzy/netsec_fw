# CPSC 526 Assignment 4 - netsec fw

CPSC 526 - Network Security - Winter 2017

Assignment 4

# Authors

Tyrone Lagore T01 (10151950) James MacIsaac T03 (10063078)

# Desc

Mock firewall which takes a set of rules as well as a bunch of 
'packets' as input and accepts/denies/drops them based on the rule file.

The rule file given as a program argument is able to run both full line and inline comments
It can also handle poorly formatted lines.

# Running the program

This program requires that you have a python3 compiler available and ready to use on your machine.

The program only contains one file with executable code - 'fw.py'

To run it:

	python3 fw.py <rule file> < <packet file>

where the contents of the rule file are arguments to the program,
and the packet file is piped into std input from the command line.

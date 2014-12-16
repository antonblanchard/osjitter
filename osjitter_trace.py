#!/usr/bin/python

# Copyright (C) 2009 Anton Blanchard <anton@au.ibm.com>, IBM
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.

import sys
import getopt
import osjitter
import re
import dtl


def usage():
	print "osjitter_trace.py [file...]"
	print
	print "	-a	absolute timestamps"
	print "	-p DIR	Directory containing proc files"
	print
	sys.exit(1)


def do_one_eventfile(file):
	f = open(file, 'rb')
	buf = f.read()
	length = len(buf)
	start = 0
	while start < length:
		entry = osjitter.entry()
		start += entry.parse(buf, start)
		t.sample(entry)
	f.close()


def do_one_dtlfile(file, cpu):
	f = open(file, 'rb')
	buf = f.read(48 * 1048576)
	length = len(buf)
	start = 0
	warned = False
	while start < length:
		# Each DTL entry is two events, start and end
		entry = dtl.entry()
		entry.parse_start(buf, start, cpu)
		t.sample(entry)

		entry = dtl.entry()
		start += entry.parse_end(buf, start, cpu)
		t.sample(entry)

	f.close()


try:
	opts, args = getopt.gnu_getopt(sys.argv[1:], "ap:")
except getopt.GetoptError:
	usage()

absolute = False
procdir = '/proc'
for o, a in opts:
	if o in ("-a"):
		absolute = True
	if o in ("-p"):
		procdir = a

if args == []:
	usage()

files = args

t = osjitter.trace(procdir=procdir)

rdtl = re.compile(".*cpu-(\d+)")
revents = re.compile(".*events-(\d+)")
for file in files:
	isdtl = rdtl.search(file)
	isevents = revents.search(file)
	if isdtl:
		# The hypervisor gives us physical CPU ids in the log, so we
		# use the filename to guess the Linux CPU id.
		cpu = int(isdtl.group(1))
		do_one_dtlfile(file, cpu)
	elif isevents:
		do_one_eventfile(file)
	else:
		print "Unknown file %s" % file

t.print_results(absolute=absolute)

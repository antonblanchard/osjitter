#!/usr/bin/python

# Copyright (C) 2009 Anton Blanchard <anton@au.ibm.com>, IBM
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.

import os
import time
import sys
import getopt
import subprocess
from signal import signal, SIGTERM
import re
import shutil
import resource

eventdir = '/sys/kernel/debug/osjitter'
dtldir = '/sys/kernel/debug/powerpc/dtl'
outdir = None
sleeptime = 30


def usage():
	print "osjitter_log.py -o outputdir [command...]"
	sys.exit(1)


try:
	opts, args = getopt.gnu_getopt(sys.argv[1:], "o:s:")
except getopt.GetoptError:
	usage()

for o, a in opts:
	if o in ("-o"):
		outdir = a
	if o in ("-s"):
		sleeptime = int(a)

if outdir == None:
	usage()

if args:
	p = subprocess.Popen(args)

try:
	os.makedirs(outdir)
except:
	pass

hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
resource.setrlimit(resource.RLIMIT_NOFILE, (hard_limit, hard_limit))

fds = []
r = re.compile('events-\d+$')
for file in os.listdir(eventdir):
	if r.match(file):
		try:
			ifd = open(os.path.join(eventdir, file), 'rb')
			ofd = open(os.path.join(outdir, file), 'wb')
			fds.append((ifd, ofd))
		except:
			pass

		# flush old data
		junk = ifd.read()

if os.path.exists(dtldir):
	r = re.compile('cpu-\d+$')
	for file in os.listdir(dtldir):
		if r.match(file):
			try:
				ifd = open(os.path.join(dtldir, file), 'rb', 0)
				ofd = open(os.path.join(outdir, file), 'wb')
				fds.append((ifd, ofd))
				# DTL only logs while open, no need to flush old data
			except:
				pass


# Normal exit when killed
signal(SIGTERM, lambda signum, stack_frame: exit(1))

while True:
	try:
		for (ifd, ofd) in fds:
			# dtl wants 48 byte aligned reads, just do it always
			data = ifd.read(48 * 1048576)
			ofd.write(data)

		if args:
			for i in range(sleeptime):
				exit_pid = os.waitpid(p.pid, os.WNOHANG)[0]
				if exit_pid:
					raise SystemExit
				time.sleep(1)
		else:
			time.sleep(sleeptime)

	except (KeyboardInterrupt, SystemExit):
		shutil.copy('/proc/cpuinfo', outdir)
		shutil.copy('/proc/kallsyms', outdir)
		shutil.copy('/proc/interrupts', outdir)
		for (ifd, ofd) in fds:
			# dtl wants 48 byte aligned reads, just do it always
			data = ifd.read(48 * 1048576)
			ofd.write(data)
			ofd.close()
		raise

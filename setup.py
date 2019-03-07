#!/usr/bin/env python3
import os
import sys

def uninstall_parts(package):
	pass

if 'uninstall' in sys.argv:
	print('Uninstall complete')
	sys.exit(0)

#INSTALL IT
#the_version = open("VERSION").read().strip()
from distutils.core import setup
s = setup(name='vtscan',
	version="1.0.2",
	description='Utility to scan for malicious files using the VirusTotal API.',
	license='MIT',
	author='Prahlad Yeri',
	author_email='prahladyeri@yahoo.com',
	url='https://github.com/prahladyeri/vtscan',
	#py_modules=['hotspotd','cli'],
	packages=['vtscan'],
	package_dir={'vtscan': ''},
	package_data={'vtscan': ['./']},
	scripts=['./vtscan', './config.json']
	#data_files=[('config',['run.dat'])],
	)

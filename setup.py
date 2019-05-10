#!/usr/bin/env python3
import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

s = setup(
	name='vtscan',
	version="1.0.3",
	license='MIT',
	description='Utility to scan for malicious files using the VirusTotal API.',
	long_description=read("README.md"),
	long_description_content_type='text/markdown',
	keywords="security,scanner",
	url='https://github.com/prahladyeri/vtscan',
	packages=find_packages(),
	#scripts=['./config.json'],
	#package_data={'vtscan': ['config.json']},
	include_package_data=True,
	entry_points={
		"console_scripts": [
			"vtscan = vtscan.vtscan:main",
		],
	},
	install_requires=['requests'],
	author='Prahlad Yeri',
	author_email='prahladyeri@yahoo.com',
	)

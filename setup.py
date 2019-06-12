#!/usr/bin/env python3
import os
import vtscan
from vtscan import __version__, __description__, __author__, __email__, __license__
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

s = setup(
	name='vtscan',
	version=__version__,
	license=__license__,
	description=__description__,
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
	author=__author__,
	author_email=__email__,
	)

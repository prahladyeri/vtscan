#!/usr/bin/env python3
import os
import vtscan
from vtscan import __version__, __description__, __author__, __email__, __license__
from setuptools import setup, find_packages
from setuptools.command.install import install
import shutil

pkg_name = 'vtscan'

class PostInstallCommand(install):
	"""Post-installation for installation mode."""
	def run(self):
		install.run(self)
		fpath = os.path.join(self.install_lib, pkg_name)
		fpath = os.path.join(fpath, "cfg.json")
		cfg_dir = os.path.join(os.path.expanduser("~"), ".config/%s" % pkg_name)
		if not os.path.isdir(cfg_dir): os.makedirs(cfg_dir)
		tpath = os.path.join(cfg_dir, "cfg.json")
		shutil.move(fpath, tpath)


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

s = setup(
	name=pkg_name,
	version=__version__,
	license=__license__,
	description=__description__,
	long_description=read("README.md"),
	long_description_content_type='text/markdown',
	url='https://github.com/prahladyeri/%s' % pkg_name,
	packages=find_packages(),
	include_package_data=True,
	entry_points={
		"console_scripts": [
			"vtscan = vtscan.vtscan:main",
		],
	},
	install_requires=['cfgsaver', 'requests', 'colorama'],
	python_requires = ">= 3.4",
	author=__author__,
	author_email=__email__,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
	cmdclass={
		'install': PostInstallCommand,
	},
	)

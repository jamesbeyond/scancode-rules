#!/usr/bin/env python

# Copyright (c) 2021 Arm Limited
# SPDX-License-Identifier: Apache-2.0


from __future__ import absolute_import
from __future__ import print_function

from glob import glob
from os.path import basename
from os.path import join
from os.path import splitext

from setuptools import find_packages
from setuptools import setup


desc = '''A ScanCode post-scan plugin to to illustrate the creation of a simple post-scan plugin.'''

setup(
    name='scancode-rules',
    version='1.0.0',
    license='Apache-2.0 with ScanCode acknowledgment',
    description=desc,
    long_description=desc,
    author='Qinghao. shi',
    author_email='info@aboutcode.org',
    url='https://github.com/nexB/scancode-toolkit/plugins/scancode-categories',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Utilities',
    ],
    keywords=[
        'scancode', 'plugin', 'post-scan'
    ],
    install_requires=[
        'scancode-toolkit',
    ],
    entry_points={
        'scancode_post_scan': [
            'rules = rules_scancode.rules_scancode:ValidateRules',
        ],
    }
)

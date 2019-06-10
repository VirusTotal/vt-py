# Copyright 2019 The vt-py authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from distutils.util import convert_path
import setuptools
import sys

main_ns = {}
with open(convert_path('vt/version.py')) as ver_file:
  exec(ver_file.read(), main_ns)

with open("README.md", "r") as fh:
  long_description = fh.read()

if sys.version_info < (3, 5, 0):
  raise RuntimeError("vt-py requires Python 3.5.0+")

install_requires = [
    'asks>=1.3.6'
    'pytest',
    'pytest_httpserver',
    'trio>=0.11.00',
]

setuptools.setup(
    name='vt-py',
    version=main_ns['__version__'],
    description="The official Python client library for VirusTotal",
    license='Apache 2',
    long_description=long_description,
    url="https://github.com/VirusTotal/vt-py",
    packages=['vt'],
    python_requires='>=3.5.0',
    install_requires=install_requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache v2 License",
        "Operating System :: OS Independent",
    ])
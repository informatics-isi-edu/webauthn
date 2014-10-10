
#
# Copyright 2012 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from distutils.core import setup

setup(
    name="webauthn2",
    description="web app security context management system",
    version="0.1-prerelease",
    packages=["webauthn2", "webauthn2.providers"],
    requires=["web.py", "pytz", "psycopg2", "oauth", "suds"],
    maintainer_email="support@misd.isi.edu",
    license='Apache License, Version 2.0',
    classifiers=[
      "Intended Audience :: Developers",
      "License :: OSI Approved :: Apache Software License",
      "Programming Language :: Python",
      "Topic :: Internet :: WWW/HTTP",
      "Topic :: Software Development :: Libraries :: Python Modules"
    ])


#
# Copyright 2012-2015 University of Southern California
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

import distutils.sysconfig
from distutils.core import setup
import sys

# this will be relative to sys.prefix e.g. /usr/share/webauthn2
datadir = 'share/webauthn2'

setup(
    name="webauthn2",
    description="web app security context management system",
    version="0.1-prerelease",
    packages=["webauthn2", "webauthn2.providers"],
    scripts=["bin/webauthn2-db-init", "bin/webauthn2-manage", "bin/webauthn2-deploy"],
    package_data={
        'webauthn2': ['webauthn2.wsgi'],
    },
    data_files=[
        (datadir, [
            "samples/wsgi_webauthn2.conf",
        ]),
        (datadir + '/database', [
            "samples/database/webauthn2_config.json",
        ]),
        (datadir + '/globus_auth', [
            "samples/globus_auth/webauthn2_config.json",
            "samples/globus_auth/client_secret_globus.json",
            "samples/globus_auth/discovery_globus.json",
        ])
    ],
    requires=["web.py", "pytz", "psycopg2", "oauth", "oauth2client", "pyjwkest"],
    maintainer_email="support@misd.isi.edu",
    license='Apache License, Version 2.0',
    classifiers=[
      "Intended Audience :: Developers",
      "License :: OSI Approved :: Apache Software License",
      "Programming Language :: Python",
      "Topic :: Internet :: WWW/HTTP",
      "Topic :: Software Development :: Libraries :: Python Modules"
    ])

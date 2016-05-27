#!/bin/python

from webauthn2 import util

print("Content-type: text/plain\n\n")

print(str(util.session_from_environment()))

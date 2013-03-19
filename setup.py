#!/usr/bin/env python3

from distutils.core import setup
from kvmc import __version__
setup(name='kvmc',
      version=str(__version__),
      author="Kandalintsev Alexandre",
      author_email='spam@messir.net',
      license="GPLv3",
      description="KVM Commander, a tool to manage your virtual machines",
      py_modules=["kvmc"],
      #packages=['useful'],
      #package_dir = {'useful': './'}
)

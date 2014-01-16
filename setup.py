#!/usr/bin/env python3

from distutils.core import setup
from kvmc import __version__
setup(name='libvmc',
      version=str(__version__),
      author="Kandalintsev Alexandre",
      author_email='spam@messir.net',
      license="GPLv3",
      description="KVM Commander, a tool to manage your virtual machines",
      py_modules=["libvmc"],
      data_files=[
        ('/usr/lib/systemd/system', ['vmc.service'])
      ]

)

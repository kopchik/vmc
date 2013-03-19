#!/usr/bin/env python3

from kvmc import KVM, Bridged, Drive, main


class Default(KVM):
  mem   = 384
  cpu   = "phenom"
  cores = 1
  net   = None
  auto  = True
  drives= []
  cmd   = "qemu-system-x86_64 --enable-kvm -curses"
  template = True


class LOR(Default):
  mem = 2048
  net = [Bridged(nic="lor", model='virtio', mac="52:54:16:12:34:66", br="intbr")]
  drives = [Drive("/home/exe/lor.qcow2", cache="unsafe")]


main()
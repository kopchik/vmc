#!/usr/bin/env python3

from kvmc import KVM, Bridged, Drive, main

class Default(KVM):
  mem   = 384
  cpu   = "phenom"
  cores = 1
  cmd   = "qemu-system-x86_64 --enable-kvm -curses"
  auto  = False


lor = Default(
  name = "lor",
  mem = 2048,
  net = [Bridged(ifname="lor", model='virtio-net',
         mac="52:54:16:12:34:66", br="intbr")],
  drives = [Drive("/home/exe/lor.qcow2",
            iface="ide", cache="unsafe")])


if __name__ == '__main__':
  main()

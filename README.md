vmc
====

Virtual machine commander (VMC) is a small replacement for monsters like libvirt.
It has a small number of dependencies and, unlike other tools, is very
easy to configure. 

**Warning:** do not forget to edit /etc/qemu/bridge.conf if you need
bridging functionality.

Example of usage:

1. Install useful: **sudo easy_install http://github.com/kopchik/useful/tarball/master**

1. Install tmux

1. Install vmc: **sudo python3 ./setup.py install** (or any other way recommended by your distro).


1. Create an executable config like that:

~~~
[root@newmaster virtuals]# cat /usr/local/bin/vmc
#!/usr/bin/env python3
from libvmc import KVM, Bridge, Bridged, Drive, main

# create bridges
intbr = Bridge("intbr")
extbr = Bridge("extbr", ifs=['eth0'])

# create a default VM template
class Default(KVM):
  mem   = 512  # RAM size in megs
  cpu   = "phenom"
  cores = 1
  auto  = True  # start VM on autostart command
  cmd   = "qemu-system-x86_64 -enable-kvm -curses"  # CMD to run


virt1 = Default(
  name   = "virt1",
  mem    = 1024,
  drives = [Drive("/home/virtuals/virt1.raw")],
  net    = [Bridged(ifname="virt1_ext", model='e1000', mac="00:50:56:00:37:24", br=extbr),
            Bridged(ifname="virt1_int", model='e1000', mac="52:54:19:12:34:59", br=intbr),])


virt2 = Default(
  name   = "virt2",
  mem    = 512,
  drives = [Drive("/home/virtuals/virt2.raw")],
  net    = [Bridged(ifname="virt2", model='e1000', mac="52:54:25:12:34:59", br=extbr)])


if __name__ == '__main__':
  main()
~~~

1. chown +x /usr/local/bin/vmc

1. Now you can run it:

~~~
[root@newmaster virtuals]# vmc status
virt1
  DOWN

virt2
  DOWN

[root@newmaster virtuals]# vmc start virt2   # or you can do "vmc virt2 as well"
[root@newmaster virtuals]# vmc status virt2
virt2
  UP (pid 31313)

[root@newmaster virtuals]# vmc   # without arguments it will print status of all machines
virt1
  DOWN

virt2
  UP (pid 31313)

~~~

1. To see the console of VM: **vmc console <VMNAME>**

1. ...

1. Profit!

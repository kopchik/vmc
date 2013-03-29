vmc
====

Virtual machine commander (VMC) is a small replacement for monsters like libvirt.
It has a small number of dependencies and, unlike other tools, is very
easy to configure. 

**Warning:** do not forget to edit /etc/qemu/bridge.conf if you need
bridging functionality.

Example of usage:

1. Install it through **sudo python3 ./setup.py install** (or any other way recommended by your distro).

1. Create an executable config like that:

~~~
[root@newmaster virtuals]# cat /usr/local/bin/vmc
#!/usr/bin/env python3

from libvmc import KVM, Bridged, Drive, main

class Default(KVM):
  mem   = 512
  cpu   = "phenom"
  cores = 1
  net   = None
  auto  = True
  cmd   = "qemu-system-x86_64 --enable-kvm -curses"


stuff = Default(
  name   = "stuff",
  mem    = 1024,
  drives = [Drive("/home/virtuals/stuff.raw")],
  net    = [Bridged(ifname="stuff_ext", model='e1000', mac="00:50:56:00:37:24", br="extbr"),
            Bridged(ifname="stuff_int", model='e1000', mac="52:54:19:12:34:59", br="intbr"),])

kliga = Default(
  name   = "kliga",
  mem    = 512,
  drives = [Drive("/home/virtuals/kliga.raw")],
  net    = [Bridged(ifname="kliga", model='e1000', mac="52:54:25:12:34:59", br="extbr")])


f __name__ == '__main__':
  main()
~~~

1. chown +x /usr/local/bin/vmc

1. Now you can run it:

~~~
[root@newmaster virtuals]# vmc status
stuff
  DOWN

b00
  DOWN

[root@newmaster virtuals]# vmc start b00   # or you can do "vmc b00 as well"
[root@newmaster virtuals]# vmc status b00
b00
  UP (pid 31313)

[root@newmaster virtuals]# vmc   # withour arguments it will print status of all machines
stuff
  DOWN

b00
  UP (pid 31313)

~~~

1. ...

1. Profit!

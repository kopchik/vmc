#!/usr/bin/env python3
from functools import reduce
from useful.tmux import TMUX
from useful.log import Log
import errno
import os

#TODO: why reduce doesn't work?
def stringify(iterable):
  # return reduce(lambda x, y: str(x)+str(y)+" ", iterable)
  r = ""
  for it in iterable:
    r += str(it)
  return r+" "


class KVM:
  name = None
  mem  = 256
  cores = 1
  cpu = "qemu64"
  runas = None
  tmux = TMUX(session="virt")

  def __init__(self):
    self.name = self.name or self.__class__.__name__
    self.pidfile = "/var/tmp/kvm_%s.pid" % self.name
    self.monfile = "/var/tmp/kvm_%s.mon" % self.name
    self.log = Log("KVM %s" % self.name)

  def __str__(self):
    cmd = self.cmd
    cmd += " -name %s" % self.name
    cmd += " -m %s" % self.mem
    cmd += " -cpu %s" % self.cpu
    cmd += " -smp %s" % self.cores
    cmd += " -monitor unix:%s,server,nowait " % self.monfile
    cmd += " -pidfile %s " % self.pidfile
    cmd += stringify(self.net)
    cmd += stringify(self.drives)
    if self.runas:
      if os.geteuid() != 0:
        cmd = "sudo " + cmd
      cmd += " -runas %s" % self.runas
    return cmd

  def is_running(self):
      try:
        pid = int(open(self.pidfile).readline().strip())
      except IOError as err:
        if err.errno == errno.EACCES:
          raise StatusUnknown("cannot read pidfile:", err)
        elif err.errno == errno.ENOENT:
          return False
        raise

      try:
        os.kill(pid, 0)
        return pid
      except ProcessLookupError:
        os.unlink(self.pidfile)
        return False

  def start(self):
    if self.is_running():
      self.log.error("Instance is already started!")
      return False

    self.log.debug("spawning %s" % self)
    self.tmux.run(self.cmd, name=self.name)

  #TODO: check its uniqueness
  def gen_mac(self):
    #from http://mediakey.dk/~cc/generate-random-mac-address-for-e-g-xen-guests/
    mac = [ 0x52, 0x54, 0x00,
    random.randint(0x00, 0xff),
    random.randint(0x00, 0xff),
    random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

  def kill(self):
    pid = self.is_running()
    if not pid:
      return
    os.kill(pid, signal.SIGTERM)

  def send_cmd(self, cmd):
    if isinstance(cmd, str):
      cmd = cmd.encode()
    if not cmd.endswith(b'\n'):
      cmd += b'\n'

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1)
    log.debug("connecting to %s" % self.monfile)
    s.connect(self.monfile)
    s.send(cmd)
    answer = s.recv(BUF_SIZE)
    if len(answer) == BUF_SIZE:
      log.error("too long answer was truncated :(")
    log.notice(answer.decode(errors='replace'))
    return answer

  def reboot(self):
    self.send_cmd("sendkey ctrl-alt-delete")

  def shutdown(self):
    self.send_cmd("system_powerdown")

  def reset(self):
    self.send_cmd("system_reset")

  def print_status(self):
    print("{name}".format(name=self.name))
    try:
      pid = self.is_running()
      status = "UP (pid %s)" % pid if pid else "DOWN"
    except StatusUnknown as err:
      status = "UNKNOWN (%s)" % err
    print ("  status:", status)

  def __repr__(self):
    return "<KVM(name=\"{name}\")>".format(name=self.name)


class Bridged:
  def __init__(self, nic, model, mac, br):
    self.nic   = nic
    self.model = model
    self.mac   = mac  # TODO: validate MAC
    self.br    = br

  def __str__(self):
    cmd = "-net nic,model={model},macaddr={mac} -net bridge,br={br}" \
           .format(model=self.model, br=self.br, mac=self.mac)
    return cmd


class Drive:
  def __init__(self, path, cache="writeback"):
    self.path = path
    self.cache = cache

  def __str__(self):
    cmd = "-drive file={path},cache={cache}" \
          .format(path=self.path, cache=self.cache)
    return cmd


class Default(KVM):
  mem   = 384
  cpu   = "phenom"
  cores = 1
  net   = None
  auto  = True
  drives= []
  cmd   = "qemu-system-x86_64 --enable-kvm -curses"


class LOR(Default):
  mem = 2048
  net = [Bridged(nic="lor", model='virtio', mac="52:54:16:12:34:66", br="intbr")]
  drives = [Drive("/home/exe/lor.qcow2", cache="unsafe")]


# b = Bridged(nic="lor", model='virtio', mac="blah-blah", br="extbr")
kvm = LOR()
kvm.start()
#!/usr/bin/env python3
from useful.cli  import CLI, command
from useful.tmux import TMUX
from useful.log import Log

from collections import OrderedDict
from functools import reduce
import argparse
import socket
import signal
import errno
import time
import sys
import os

__version__ = 7
CONFIGS = list(map(os.path.expanduser, ['~/kvmc.cfg', '/etc/kvmc.cfg']))
BUF_SIZE = 65535
log = Log("KVMC")

#TODO: why reduce doesn't work?
def stringify(iterable):
  # return reduce(lambda x, y: str(x)+str(y)+" ", iterable)
  r = ""
  for it in iterable:
    r += str(it)
  return r+" "


kvms = OrderedDict()
class MetaKVM(type):
  def __init__(cls, name, bases, ns):
    global kvms
    if not ns.get('template', False):
      assert name not in kvms, "duplicate name: %s" % name
      kvms[name] = cls()


class KVM(metaclass=MetaKVM):
  name = None
  mem  = 256
  cores = 1
  cpu = "qemu64"
  runas = None
  tmux = TMUX(socket="virt", session="KVM")
  template = True

  def __init__(self):
    self.name = self.name or self.__class__.__name__
    self.pidfile = "/var/tmp/kvm_%s.pid" % self.name
    self.monfile = "/var/tmp/kvm_%s.mon" % self.name
    self.log = Log("KVM %s" % self.name)

  def get_cmd(self):
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

    self.log.debug("spawning %s" % self.get_cmd())
    self.tmux.run(self.get_cmd(), name=self.name)

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
    self.log.debug("connecting to %s" % self.monfile)
    s.connect(self.monfile)
    s.send(cmd)
    answer = s.recv(BUF_SIZE)
    if len(answer) == BUF_SIZE:
      self.log.error("too long answer was truncated :(")
    self.log.notice(answer.decode(errors='replace'))
    return answer

  def console(self):
    self.tmux.attach(name=self.name)

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
    return "KVM(\"{name}\")".format(name=self.name)


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
  def __init__(self, path, iface="virtio", cache="writeback"):
    self.path  = path
    self.cache = cache
    self.iface = iface

  def __str__(self):
    cmd = "-drive file={path},if={iface},cache={cache}" \
          .format(path=self.path, iface=self.iface, cache=self.cache)
    return cmd


class CMD(CLI):
    def __init__(self, instances):
        self.instances = instances

    @command("list")
    def do_list(self):
        for kvm in self.instances:
            print(kvm)

    @command("start all")
    def do_start_all(self):
        sleep = 0
        log.debug("starting all stopped instances")
        for instance in self.instances.values():
            time.sleep(sleep)
            if instance.is_running():
                log.debug("skipping %s because it is already started" % instance)
                continue
            log.info("Starting %s" % instance)
            instance.start()
            sleep = 3

    @command("[name] start")
    @command("start [name]")
    def do_start(self, name=None):
        if name not in self.instances:
            fatal_error("no such instance: %s" % name)
        print("Starting %s" % name)
        self.instances[name].start()

    @command("console [name]")
    @command("[name] console")
    def do_console(self, name=None):
        print("attaching", name)
        if name and not self.instances[name].is_running():
                sys.exit("Instance is not started")
        self.instances[name].tmux.attach(name=name)

    @command("status")
    def do_status(self):
        for instance in self.instances.values():
            instance.print_status()

    @command("shutdown all")
    def do_shutdown(self, name=None):
      for instance in self.instances.values():
        if instance.is_running():
          instance.shutdown()

    @command("[name] shutdown")
    @command("shutdown [name]")
    def do_shutdown(self, name=None):
        self.instances[name].shutdown()

    @command("kill all")
    def do_kill_all(self):
        for instance in self.instances.values():
            instance.kill()

    @command("[name] kill")
    @command("kill [name]")
    def do_kill(self, name=None):
        self.instances[name].kill()

    @command("[name] reboot")
    @command("reboot [name]")
    def do_reboot(self, name=None):
        self.instances[name].reboot()

    @command("[name] reset")
    @command("reset [name]")
    def do_reset(self, name=None):
        self.instances[name].reset()


def main():
  parser = argparse.ArgumentParser(
    description='KVM commander version %s' % __version__)
  parser.add_argument('-d', '--debug', action='store_true',
                      default=False, help="enable debug output")
  parser.add_argument('-v', '-V', '--version', action='store_true',
                      default=False, help="get software version")
  parser.add_argument('cmd', default=["status"], nargs="*",
    help="command to execute")
  args = parser.parse_args()
  print("arguments:", args, file=sys.stderr)

  if args.version:
    return print("Software version:", __version__)

  if args.debug:
    log.verbosity = "debug"

  cmd = CMD(kvms)
  cmd.run_cmd(" ".join(args.cmd))

#!/usr/bin/env python3
from useful.cli  import CLI, command
from useful.tmux import TMUX
from useful.log import Log

from collections import OrderedDict
from functools import reduce
import argparse
import warnings
import random
import socket
import signal
import errno
import time
import sys
import os

__version__ = 7
KILL_TIMEOUT = 10
POLL_INTERVAL = 0.1
BUF_SIZE = 65535
log = Log("KVMC")

#TODO: why reduce doesn't work?
def stringify(iterable):
  # return reduce(lambda x, y: str(x)+str(y)+" ", iterable)
  r = ""
  for it in iterable:
    r += str(it)
  return r+" "

def gen_mac():
  #TODO: check its uniqueness
  #from http://mediakey.dk/~cc/generate-random-mac-address-for-e-g-xen-guests/
  mac = [ 0x02, 0x00, 0x00,
  random.randint(0x00, 0xff),
  random.randint(0x00, 0xff),
  random.randint(0x00, 0xff) ]
  return ':'.join(map(lambda x: "%02x" % x, mac))


class UnknownInstance(Exception):
  """no such machine"""


class Manager(CLI):
  """ class to orchestrate several instances at once """
  def __init__(self, name="default"):
    self.instances = OrderedDict()
    self.name = name
    self.log  = Log(name)

  def add_instance(self, inst):
    self.instances[inst.name] = inst

  def check_instance(self, name):
    if name not in self.instances:
      raise UnknownInstance("no such instance: %s" % name)

  @command("gen mac")
  def genmac(self):
    print(gen_mac())

  @command("list")
  def do_list(self):
    return self.instances.keys()

  @command("autostart")
  def autostart(self):
    log.debug("starting all stopped instances with auto=True")
    sleep = 0  # do not do a pause if there is only one instance
    for instance in self.instances.values():
      time.sleep(sleep)
      if not instance.auto:
        self.log.debug("%s is skipped because it has auto=False"
                        % instance)
        continue
      if instance.is_running():
        log.debug("skipping %s because it is already started" % instance)
        continue
      log.info("Starting %s" % instance)
      instance.start()
      sleep = 3

  @command("[name] start")
  @command("start [name]")
  def start(self, name=None):
    self.log.debug("Starting %s" % name)
    self.check_instance(name)
    self.instances[name].start()

  @command("stop all")
  @command("shutdown all")
  def stop_all(self):
    for inst in self.instances.values():
      inst.stop()

  @command("stop [name]")
  @command("[name] stop")
  @command("shutdown [name]")
  @command("[name] shutdown")
  def stop(self, name):
    self.check_instance(name)
    self.instances[name].stop()

  @command("[name] reboot")
  @command("reboot [name]")
  def reboot(self, name=None):
    self.check_instance(name)
    self.instances[name].reboot()

  @command("[name] reset")
  @command("reset [name]")
  def reset(self, name=None):
    self.check_instance(name)
    self.instances[name].reset()

  @command("kill all")
  def kill_all(self):
    self.log.critical("KILLING ALL instances (even with auto=False)")
    for inst in self.instances.values():
      inst.kill()

  @command("[name] kill")
  @command("kill [name]")
  def kill(self, name):
    self.check_instance(name)
    self.instances[name].kill()

  @command("show cmd [name]")
  def show_cmd(self, name):
    print(self.instances[name].get_cmd())

  @command("console [name]")
  @command("[name] console")
  def console(self, name=None):
    self.log.debug("attaching to %s" % name)
    if name and not self.instances[name].is_running():
      sys.exit("Instance is not started")
    self.instances[name].tmux.attach(name=name)

  @command("status")
  def status(self):
    for inst in self.instances.values():
      print(inst.format_status())

  @command("wait all timeout [timeout]")
  def wait_all(self, timeout):
    timeout = int(timeout)
    t = 0
    while True:
      running = 0
      for inst in self.instances.values():
        if inst.is_running():
          running = 1
      if not running:
        break
      time.sleep(1)
      t += 1
      if t > timeout:
        raise TimeoutError("instances still running")
      print('.', end='', file=sys.stderr)

  @command("graceful stop timeout [timeout]")
  def do_graceful(self, timeout):
    self.log.info("stopping ALL instances (even with auto=False)")
    timeout = int(timeout)
    self.stop_all()
    try:
      self.wait_all(timeout)
    except TimeoutError:
      self.log.critical("kvms still running: %s" \
        % list(filter(lambda x: x.is_running(), self.instances.values())))
      self.do_kill_all()
manager = Manager("")  # default manager


class MetaKVM(type):
  """ Check the instance name and add it to its manager """
  def __init__(cls, name, bases, ns):
    #if there is no defined name we took it from class name
    if 'name' not in ns:
      cls.name = name
      mgr = cls.mgr
    if not ns.get('template', False):
      assert cls.name not in mgr.instances, "duplicate name: %s" % name
      mgr.add_instance(cls())


class KVM(metaclass=MetaKVM):
  name  = None
  mem   = 256
  cores = 1
  cpu   = "qemu64"
  runas = None
  cmd   = "qemu-system-x86_64 --enable-kvm -curses"
  tmux  = TMUX(socket="virt", session="KVM")
  template = True
  auto  = True
  net   = None
  mgr   = manager  # assigned manager, this managed by metaclass

  def __init__(self):
    # self.name = self.name or self.__class__.__name__  # this assignment is in MetaKVM 
    self.pidfile = "/var/tmp/kvm_%s.pid" % self.name
    self.monfile = "/var/tmp/kvm_%s.mon" % self.name
    self.log = Log("KVM %s" % self.name)


  def get_cmd(self):
    """ Get cmd that launches instance """
    cmd = self.cmd
    cmd += " -name %s" % self.name
    cmd += " -m %s" % self.mem
    if self.cpu: cmd += " -cpu %s" % self.cpu
    cmd += " -smp %s" % self.cores
    cmd += " -qmp unix:%s,server,nowait " % self.monfile
    cmd += " -pidfile %s " % self.pidfile
    if self.net: cmd += stringify(self.net)
    if self.drives: cmd += stringify(self.drives)
    if self.runas:
      if os.geteuid() != 0:
        cmd = "sudo " + cmd
      cmd += " -runas %s" % self.runas
    return cmd

  def is_running(self):
    """ Returns either pid of the process 
        or False if kvm is not running.
    """
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
      self.log.debug("Instance is already started!")
      return False

    self.log.debug("spawning %s" % self.get_cmd())
    self.tmux.run(self.get_cmd(), name=self.name)

  def kill(self):
    """ Kill guest using all possible means """
    pid = self.is_running()
    if not pid:
      return self.log.debug("He's Dead, Jim!")
    self.send_qmp("{'execute': 'quit'}")
    timeout = KILL_TIMEOUT
    while timeout > 0:
      time.sleep(POLL_INTERVAL)
      timeout -= POLL_INTERVAL
      if not self.is_running():
        break
    else:
      self.log.critical("It doesn't want to die, killling by SIGKILL")
      os.kill(pid, signal.SIGKILL)

  def send_qmp(self, cmd):
    if isinstance(cmd, str):
      cmd = cmd.encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1)
    self.log.debug("connecting to %s" % self.monfile)
    s.connect(self.monfile)
    s.send(b'{"execute": "qmp_capabilities"}')  # handshake
    answer = s.recv(BUF_SIZE)
    self.log.debug(answer.decode(errors='replace'))
    s.send(cmd)
    answer = s.recv(BUF_SIZE)
    if len(answer) == BUF_SIZE:
      self.log.error("too long answer was truncated :(")
    self.log.debug(answer.decode(errors='replace'))
    return answer

  def console(self):
    self.tmux.attach(name=self.name)

  def reboot(self):
    """ Send Ctrl+Alt+Del """
    data = """{ "execute": "send-key",
        "arguments": { 'keys': [
          {'type':'qcode', 'data': 'ctrl'},
          {'type':'qcode', 'data': 'alt'},
          {'type':'qcode', 'data': 'delete'}
          ]}}"""
    self.send_qmp(data)

  def shutdown(self):
    if self.is_running():
      self.send_qmp('{"execute": "system_powerdown"}')
  stop = shutdown  # stop is alias for shutdown

  def reset(self):
    """ Do hard reset """
    self.send_qmp('{"execute": "system_reset"}')

  def format_status(self):
    formated = "%s\n" % self.name
    formated += "  noauto" if not self.auto else " "
    try:
      pid = self.is_running()
      if pid:
        formated += " UP (pid %s)\n" % pid if pid else "DOWN"
      else:
        formated += " DOWN\n"
    except StatusUnknown as err:
      formated += " UNKNOWN (%s)\n" % err
    return formated

  def __repr__(self):
    return "KVM(\"{name}\")".format(name=self.name)


class Bridged:
  # TODO: make input validation
  def __init__(self, ifname, model, mac, br):
    self.model = model
    self.mac   = mac
    self.br    = br
    assert len(ifname) < 16, "too long ifname"  # linux/if.h#IFNAMSIZ
    self.ifname= ifname

  def __str__(self):
    cmd  = " -device {model},mac={mac},netdev={id}" \
            .format(model=self.model, mac=self.mac, id=self.ifname)
    if self.ifname:
      warnings.warn("ifname is likely to be supported only in qemu 1.5")
      #cmd += ",ifname=%s" % self.ifname
    cmd += " -netdev bridge,br={br},id={id}" \
            .format(br=self.br, id=self.ifname)
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
  log.debug("arguments: %s" % args)

  if args.version:
    return print("Software version:", __version__)

  if args.debug:
    log.verbosity = "debug"

  manager.run_cmd(" ".join(args.cmd))

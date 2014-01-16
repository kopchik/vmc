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

__version__ = 11
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

def gen_mac(check_unique=False):
  #TODO: check its uniqueness
  #from http://mediakey.dk/~cc/generate-random-mac-address-for-e-g-xen-guests/
  #mac = [ 0x02, 0x00, 0x00,
  mac = [ 0x52, 0x54, 0x00,
  random.randint(0x00, 0xff),
  random.randint(0x00, 0xff),
  random.randint(0x00, 0xff) ]
  return ':'.join(map(lambda x: "%02x" % x, mac))


class UnknownInstance(Exception):
  """no such machine"""


class StatusUnknown(Exception):
  """cannot get status (permission problem, etc)"""


class Manager(CLI):
  """ class to orchestrate several instances at once """
  def __init__(self, name="default"):
    self.instances = OrderedDict()
    self.name = name
    self.log  = Log(name)

  def add_instance(self, inst):
    assert inst.name not in self.instances, \
      "we already have machine with the name %s" % inst.name
    self.instances[inst.name] = inst

  def check_instance(self, name):
    if name not in self.instances:
      raise UnknownInstance("no such instance: %s" % name)

  @command("gen mac")
  def genmac(self):
    mac = gen_mac()
    print(mac)
    return mac

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
  def start(self, name):
    assert isinstance(name, str), "name should be string"
    self.log.debug("Starting %s" % name)
    self.check_instance(name)
    inst = self.instances[name]
    pid = inst.start()
    return inst

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
    while True:
      running = 0
      for inst in self.instances.values():
        if inst.is_running():
          running = 1
      if not running:
        break
      timeout -= 1
      if timeout < 0:
        raise TimeoutError("instances still running")
      time.sleep(1)
      print('.', end='', file=sys.stderr, flush=True)

  @command("graceful stop timeout [timeout]")
  def graceful(self, timeout=30):
    self.log.info("stopping ALL instances (even with auto=False)")
    timeout = int(timeout)
    self.stop_all()
    try:
      self.wait_all(timeout)
    except TimeoutError:
      self.log.critical("kvms still running: %s" \
        % list(filter(lambda x: x.is_running(), self.instances.values())))
      self.kill_all()
manager = Manager("")  # default manager


class KVM:
  name  = None
  mem   = 256
  cores = 1
  cpu   = "qemu64"
  runas = None
  cmd   = "qemu-system-x86_64 -enable-kvm -curses"
  tmux  = TMUX(socket="virt", session="KVM")
  auto  = True
  net   = None
  drives= None
  mgr   = manager  # assigned manager, this managed by metaclass

  def __init__(self, **kwargs):
    self.__dict__.update(kwargs)
    # self.name = self.name or self.__class__.__name__  # this assignment is in MetaKVM
    self.pidfile = "/var/tmp/kvm_%s.pid" % self.name
    self.monfile = "/var/tmp/kvm_%s.mon" % self.name
    self.log = Log("KVM %s" % self.name)
    assert self.name, "name is mandatory"
    if self.mgr:
      self.log.debug("adding %s to %s" % (self, self.mgr))
      self.mgr.add_instance(self)

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

  @property
  def pid(self):
    return self.is_running()

  def start(self):
    if self.is_running():
      self.log.debug("Instance is already started!")
      return False

    self.log.debug("spawning %s" % self.get_cmd())
    self.tmux.run(self.get_cmd(), name=self.name)

    for x in range(100):
        pid = self.is_running()
        if pid: return pid
        time.sleep(0.1)
        print("waiting for VM")
    raise StatusUnknown("KVM %s doesn't want to start" % self.name)

  def kill(self):
    """ Kill guest using all possible means """
    pid = self.is_running()
    if not pid:
      return self.log.debug("It's Dead, Jim!")
    try:
      self.send_qmp("{'execute': 'quit'}")
      timeout = KILL_TIMEOUT
      while timeout > 0:
        time.sleep(POLL_INTERVAL)
        timeout -= POLL_INTERVAL
        if not self.is_running():
          return
    except Exception as err:
      self.log.critical("cannot kill normally: %s" % err)
    self.log.critical("It doesn't want to die, killing by SIGKILL")
    try:
      os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
      pass

  def send_qmp(self, cmd):
    if isinstance(cmd, str):
      cmd = cmd.encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1)
    self.log.debug("connecting to %s" % self.monfile)
    s.connect(self.monfile)
    s.send(b'{"execute": "qmp_capabilities"}')  # handshake
    answer = s.recv(BUF_SIZE)
    #self.log.debug(answer.decode(errors='replace'))
    s.send(cmd)
    answer = s.recv(BUF_SIZE)
    if len(answer) == BUF_SIZE:
      self.log.error("too long answer was truncated :(")
    #self.log.debug(answer.decode(errors='replace'))
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
    """ Does not guarantee success """
    if self.is_running():
      try:
        self.send_qmp('{"execute": "system_powerdown"}')
      except Exception as err:
        self.log.critical("shutdown command failed with %s" % err)
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

  def __exit__(self):
    self.shutdown()
    for x in range(300):
      time.sleep(0.1)
      if not self.is_running():
        return
    self.log.critical("doesn't want to die, killing")
    self.kill()


class Bridged:
  # TODO: make input validation
  def __init__(self, ifname, model, mac, br, helper=None):
    self.model = model
    self.mac   = mac
    self.br    = br
    self.helper= helper
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
    if self.helper:
      cmd += ",helper={helper}".format(helper=self.helper)
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


def main(manager=manager):
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

  # TODO: rewrite this
  # if args.debug:
  #   log.verbosity = "debug"

  manager.run_cmd(" ".join(args.cmd))

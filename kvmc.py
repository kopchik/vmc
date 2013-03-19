#!/usr/bin/env python3
import exeutilz; exeutilz.exeutilz_minver(1.75)
from exeutilz.cli import CLI, command
from useful.tmux import TMUX
from useful.small import run
from useful.log import Log
import configparser
import subprocess
import argparse
import socket
import signal
import shlex
import errno
import time
import sys
import os

__version__ = 5

DEBUG = True
CONFIGS = list(map(os.path.expanduser, ['~/kvmc.cfg', '/etc/kvmc.cfg']))
BUF_SIZE = 65535
log = Log("KVMC", verbosity='info')


class StatusUnknown(Exception):
    pass


def validate_name(name):
    if name != name.strip():
        raise Exception("Name ``%s'' contains trailing"
                        "or leading whitespace characters" % name)

    if name in ["status", "kill", "start", "stop", "all", "shutdown"]:
        raise Exception("Invalid name for the machine: %s" % name)

def fatal_error(error, errno=1):
    log.error(error)
    sys.exit(errno)



class KVM(CLI):
    def __init__(self, name=None, mem=384, cores=1, sleep=0.0, cpu=None, runas=None, cmd="", tmux=None, qemu="qemu-system-x86_64 --enable-kvm"):
      self.name = name
      self.tmux = tmux
      self.sleep = float(sleep)
      self.pidfile = "/var/tmp/kvm_%s.pid" % self.name
      self.cmd = qemu + " -curses -pidfile %s " % self.pidfile
      self.monfile = "/var/tmp/kvm_%s.mon" % self.name
      self.cmd += "-monitor unix:%s,server,nowait " % self.monfile
      self.cmd += "-name %s " % self.name
      if mem:    self.cmd += "-m %s " % mem
      if cores:  self.cmd += "-smp %s " % cores
      if cpu:    self.cmd += "-cpu %s " % cpu
      if cmd:    self.cmd += cmd

      if runas:
        self.cmd = "sudo " + self.cmd # "-runas" requires root privs #TODO: check for root?
        self.cmd += " -runas %s " % runas

    def is_running(self):
        try:
          pid = int(open(self.pidfile).readline().strip())
        except IOError as err:
          if err.errno == errno.EACCES:
            raise StatusUnknown("cannot read peadfile:", err)
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
        print("Instance is already started!")
        return False

      print("spawning", self.cmd)
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


class CMD(CLI):
    def __init__(self, instances):
        self.instances = instances

    @command("list")
    def do_list(self):
        for kvm in self.instances:
            print(kvm)

    @command("[name] start")
    @command("start [name]")
    def do_start(self, name=None):
        if name not in self.instances:
            fatal_error("no such instance: %s" % name)
        print("Starting %s" % name)
        self.instances[name].start()

    @command("start all")
    def do_start_all(self):
        log.debug("starting all not started instances")
        sleep = 0
        for instance in self.instances.values():
            if sleep:
                log.debug("sleeping for %s before launchin another instance" % sleep)
            time.sleep(sleep)
            if instance.is_running():
                log.debug("skipping %s because it is allready started" % instance)
                continue
            log.info("Starting %s" % instance)
            instance.start()
            sleep = instance.sleep

    @command("console")
    @command("console [name]")
    @command("[name] console")
    def do_console(self, name=None):
        print("attaching", name)
        if name and not instances[name].is_running():
                sys.exit("Instance is not started")
        tmux.attach(name=name)

    @command("status")
    def do_status(self):
        for instance in self.instances.values():
            instance.print_status()

    @command("kill all") #TODO: doesnt work
    def do_kill_all(self):
        for instance in self.instances.values():
            instance.kill()

    @command("[name] shutdown")
    @command("shutdown [name]")
    def do_shutdown(self, name=None):
        self.instances[name].shutdown()

    @command("[name] kill")
    @command("kill [name]")
    def do_kill(self, name=None):
        instances[name].kill()

    @command("[name] reboot")
    @command("reboot [name]")
    def do_reboot(self, name=None):
        instances[name].reboot()

    @command("[name] reset")
    @command("reset [name]")
    def do_reset(self, name=None):
        instances[name].reset()

    @command("version")
    def do_print_version(self):
        print("version: ", __version__)
        print(sys.version)

    def do_default(self):
        return self.do_status()


if __name__ == '__main__':
  instances = {}
  os.unsetenv('TMUX')
  tmux = TMUX()

  parser = argparse.ArgumentParser(
    description='KVM commander version %s' % __version__)
  parser.add_argument('-d', '--debug', action='store_true',
                      default=False, help="enable debug output")
  parser.add_argument('-c', '--config', help="path to config file")
  parser.add_argument('-v', '-V', '--version', action='store_true',
                      default=False, help="get software version")
  parser.add_argument('cmd', default="status", nargs="*",
    help="command to execute")
  args = parser.parse_args()
  print(args)

  if args.version:
    print("Software version:", __version__)
    sys.exit()

  if args.debug:
    log.verbosity = "debug"

  if args.config:
    CONFIGS = [args.config]

  config = configparser.ConfigParser()
  for cfgfile in CONFIGS:
    r = config.read(cfgfile)
    if r:
      log.debug("Using config file %s" % cfgfile)
      break
  else:
    raise Exception("Cannot read any of config files (%s)" % CONFIGS)

  for name in config.sections():
    params = config[name]
    instance = KVM(tmux=tmux, name=name, **params)
    instances[name] = instance

  cmd = CMD(instances)
  cmd.run_cmd(args.cmd)

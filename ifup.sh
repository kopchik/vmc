#!/bin/sh

if [ -z "$BRIDGE" ]; then
  echo "$0: please set \$BRIDGE" 1>&2
  exit 1
fi

SUDO=''
if [ `id -u` != "0" ]; then
    SUDO=sudo
fi

$SUDO ifconfig $1 0.0.0.0 up
$SUDO brctl addif $DRIGDE $1

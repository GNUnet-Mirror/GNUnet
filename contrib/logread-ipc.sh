#!/bin/sh

ipc=${1:-/tmp/gnunet-logread-ipc.sock}
test -e "$ipc" || mkfifo "$ipc"
cat "$ipc"

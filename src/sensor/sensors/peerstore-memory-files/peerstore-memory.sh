#!/bin/sh

ps aux | grep 'gnunet-service-peerstore' | grep -v grep | awk '{ print $6 }'

#!/bin/bash

# Deploy docs from buildbot

chmod -R ag+rX doc/
rsync -a --delete doc/ handbook@firefly.gnunet.org:~/doc_deployment/

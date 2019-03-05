#!/bin/sh
#
# This essentially could be solved by:
# git config pull.rebase true
# git config rebase.autoStash true
# but chances are that this is easy to
# forget.
# so execute this file on the server
# instead of setting a git config.

echo "Running git pull with autoStash and rebase"
echo "If anything breaks in the future, delete"
echo "and repeat - it was once considered to"
echo "be responsible for non-trivial conflicts!"
echo "We apply this because we need to build the"
echo "handbook and tutorial without manual interventions."

git pull --rebase --autostash

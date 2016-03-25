#!/bin/bash
dot -Tpng `ls -tr1 /tmp/*rec*.dot | tail -1` | display /dev/stdin &

dot -Tpng `ls -tr1 /tmp/*play*.dot | tail -1` | display /dev/stdin &


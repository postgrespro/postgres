#!/bin/bash

INSTDIR=`pwd`/tmp_install
export LD_LIBRARY_PATH=$INSTDIR/lib:$LD_LIBRARY_PATH
export PATH=$INSTDIR/bin:$PATH
export PGPORT=5438
export PGHOST=localhost
export PGDATABASE=`whoami`

pkill -U `whoami` -9 -e postgres
pkill -U `whoami` -9 -e pgbench

M=`pwd`/PGDATA
U=`whoami`

rm -rf logfile.log || true
pg_ctl -w -D $M -l logfile.log start
pgbench -T 20 -c 10 -j 10 -P 5 --select-only -n $U
pg_ctl -D $M stop

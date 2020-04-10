#!/bin/bash

INSTDIR=`pwd`/tmp_install
export LD_LIBRARY_PATH=$INSTDIR/lib:$LD_LIBRARY_PATH
export PATH=$INSTDIR/bin:$PATH

pkill -U `whoami` -9 -e postgres
pkill -U `whoami` -9 -e pgbench

M=`pwd`/PGDATA
U=`whoami`

rm -rf $M || true
mkdir $M

rm -rf logfile.log || true

mk
initdb -D $M

#echo "work_mem = 2GB" >> $M/postgresql.conf
#echo "shared_buffers = 2GB" >> $M/postgresql.conf
pg_ctl -w -D $M -l logfile.log start
createdb $U
pgbench -i -s 300
pgbench -T 60 -c 15 -j 15 -P 5 --select-only -n $U


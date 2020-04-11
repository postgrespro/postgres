#!/bin/bash

# ##############################################################################
#
# Use pgbench to scale OLTP load with FDW + partitioning machinery
#
# ##############################################################################

PGINSTALL=`pwd`/tmp_install/

export LD_LIBRARY_PATH=$PGINSTALL/lib:$LD_LIBRARY_PATH
export PATH=$PGINSTALL/bin:$PATH

export PGDATABASE=shardman
export PGHOST=localhost
export PGUSER=`whoami`

pkill -U `whoami` -9 -e postgres
pkill -U `whoami` -9 -e pgbench

pg_ctl -D PGDATA1 -l n0.log start
pg_ctl -o "-p 5433" -D PGDATA2 -l n1.log start
pg_ctl -o "-p 5434" -D PGDATA3 -l n2.log start

pgbench -p 5432 -T 60 -P 5 -c 100 -j 33 --select-only -n &
pgbench -p 5433 -T 60 -P 5 -c 100 -j 33 --select-only -n &
pgbench -p 5434 -T 60 -P 5 -c 100 -j 33 --select-only -n &


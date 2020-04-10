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

pgbench -p 5432 -T 60 -P 5 -c 5 -j 5 --select-only -n &
pgbench -p 5433 -T 60 -P 5 -c 5 -j 5 --select-only -n &
pgbench -p 5434 -T 60 -P 5 -c 5 -j 5 --select-only -n &


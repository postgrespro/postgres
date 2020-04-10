#!/bin/bash

# ##############################################################################
#
# Deploy local 3-node configuration of sharded postgres.
#
# This script performs initialization of fdw+partitioning infrastructure for
# parallel (distributed) query execution purposes.
#
# ##############################################################################

PGINSTALL=`pwd`/tmp_install/
DEPLOY_SCRIPTS_PATH=`pwd`
SCALE=100

export LD_LIBRARY_PATH=$PGINSTALL/lib:$LD_LIBRARY_PATH
export PATH=$PGINSTALL/bin:$PATH
export LC_ALL=C
export LANGUAGE="en_US:en"
export PGPORT=5432 #default head
export PGDATABASE=shardman
export PGHOST=localhost
export PGUSER=`whoami`

pkill -U `whoami` -9 -e postgres
pkill -U `whoami` -9 -e pgbench

D1=`pwd`/PGDATA1
D2=`pwd`/PGDATA2
D3=`pwd`/PGDATA3

rm -rf $D1 && mkdir $D1 && rm -rf $D2 && mkdir $D2 && rm -rf $D3 && mkdir $D3
rm -rf $PGINSTALL && rm n0.log && rm n1.log && rm n2.log

# Building project
make > /dev/null
make -C contrib > /dev/null
make install > /dev/null
make -C contrib install > /dev/null

remoteSrvName=fdwremote

initdb -D $D1 -E UTF8 --locale=C
initdb -D $D2 -E UTF8 --locale=C
initdb -D $D3 -E UTF8 --locale=C

echo "shared_preload_libraries = 'postgres_fdw'" >> $D1/postgresql.conf
echo "shared_preload_libraries = 'postgres_fdw'" >> $D2/postgresql.conf
echo "shared_preload_libraries = 'postgres_fdw'" >> $D3/postgresql.conf
echo "shared_buffers = 10GB" >> $D1/postgresql.conf
echo "shared_buffers = 10GB" >> $D2/postgresql.conf
echo "shared_buffers = 10GB" >> $D3/postgresql.conf
echo "listen_addresses = '*'" >> $D1/postgresql.conf
echo "listen_addresses = '*'" >> $D2/postgresql.conf
echo "listen_addresses = '*'" >> $D3/postgresql.conf
echo "host    all             all             0.0.0.0/0                 trust" >> $D1/pg_hba.conf
echo "host    all             all             0.0.0.0/0                 trust" >> $D2/pg_hba.conf
echo "host    all             all             0.0.0.0/0                 trust" >> $D3/pg_hba.conf

# Takeoff
pg_ctl -w -c -o "-p 5434" -D $D3 -l n2.log start
pg_ctl -w -c -o "-p 5433" -D $D2 -l n1.log start
pg_ctl -w -c -o "-p 5432" -D $D1 -l n0.log start
createdb -p 5432
createdb -p 5433
createdb -p 5434

# Init foreign tables
psql -p 5434 -c "CREATE EXTENSION postgres_fdw;"
psql -p 5433 -c "CREATE EXTENSION postgres_fdw;"
psql -p 5432 -c "CREATE EXTENSION postgres_fdw;"

# Create pgbench partitions
pgbench -p 5432 -i -s $SCALE --partitions=3 --partition-method=hash
pgbench -p 5433 -i -s $SCALE --partitions=3 --partition-method=hash
pgbench -p 5434 -i -s $SCALE --partitions=3 --partition-method=hash

# Drop unneeded local partitions and init foreign partitions
psql -p 5432 -f "$DEPLOY_SCRIPTS_PATH/n0_pgb_init.sql"
psql -p 5433 -f "$DEPLOY_SCRIPTS_PATH/n1_pgb_init.sql"
psql -p 5434 -f "$DEPLOY_SCRIPTS_PATH/n2_pgb_init.sql"

# The end of deploy


# Create tables pt,rt,st partitioned by hash on id column.
#psql -p 5432 -f "$DEPLOY_SCRIPTS_PATH/init_node0.sql"
#psql -p 5433 -f "$DEPLOY_SCRIPTS_PATH/init_node1.sql"
#psql -p 5434 -f "$DEPLOY_SCRIPTS_PATH/init_node2.sql"

# Fill the pt relation
#psql -p 5432 -c \
#	"INSERT INTO pt (id, payload, test)
#	(
#		SELECT a.*, b.*,0
#	);"


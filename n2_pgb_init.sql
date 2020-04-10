CREATE SERVER remote1 FOREIGN DATA WRAPPER postgres_fdw	OPTIONS (port '5432', use_remote_estimate 'on');
CREATE USER MAPPING FOR PUBLIC SERVER remote1;
CREATE SERVER remote2 FOREIGN DATA WRAPPER postgres_fdw OPTIONS (port '5433', use_remote_estimate 'on');
CREATE USER MAPPING FOR PUBLIC SERVER remote2;

DROP TABLE pgbench_accounts_1 CASCADE;
DROP TABLE pgbench_accounts_2 CASCADE;
ALTER TABLE pgbench_accounts DROP CONSTRAINT pgbench_accounts_pkey;

DROP TABLE pgbench_branches_1 CASCADE;
DROP TABLE pgbench_branches_2 CASCADE;
ALTER TABLE pgbench_branches DROP CONSTRAINT pgbench_branches_pkey;

DROP TABLE pgbench_tellers_1 CASCADE;
DROP TABLE pgbench_tellers_2 CASCADE;
ALTER TABLE pgbench_tellers DROP CONSTRAINT pgbench_tellers_pkey;

CREATE FOREIGN TABLE pgbench_accounts_1 PARTITION OF pgbench_accounts FOR VALUES WITH (modulus 3, remainder 0) SERVER remote1;
CREATE FOREIGN TABLE pgbench_accounts_2 PARTITION OF pgbench_accounts FOR VALUES WITH (modulus 3, remainder 1) SERVER remote2;
ALTER TABLE pgbench_accounts ADD PRIMARY KEY (aid);

CREATE FOREIGN TABLE pgbench_branches_1 PARTITION OF pgbench_branches FOR VALUES WITH (modulus 3, remainder 0) SERVER remote1;
CREATE FOREIGN TABLE pgbench_branches_2 PARTITION OF pgbench_branches FOR VALUES WITH (modulus 3, remainder 1) SERVER remote2;
ALTER TABLE pgbench_branches ADD PRIMARY KEY (bid);

CREATE FOREIGN TABLE pgbench_tellers_1 PARTITION OF pgbench_tellers FOR VALUES WITH (modulus 3, remainder 0) SERVER remote1;
CREATE FOREIGN TABLE pgbench_tellers_2 PARTITION OF pgbench_tellers FOR VALUES WITH (modulus 3, remainder 1) SERVER remote2;
ALTER TABLE pgbench_tellers ADD PRIMARY KEY (tid);


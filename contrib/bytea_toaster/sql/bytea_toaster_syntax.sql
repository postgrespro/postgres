CREATE EXTENSION bytea_toaster;

CREATE TABLE tst_failed (
	t jsonb TOASTER bytea_toaster
);

CREATE TABLE tst1 (
	t bytea TOASTER bytea_toaster
);

DROP EXTENSION bytea_toaster;

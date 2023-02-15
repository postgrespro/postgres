#ifndef TOASTAPISQL_H
#define TOASTAPISQL_H


#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "toastapi.h"
#include "access/toast_helper.h"

#include "access/htup_details.h"
#include "commands/defrem.h"
#include "lib/pairingheap.h"
#include "utils/builtins.h"
#include "utils/memutils.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/reloptions.h"
#include "access/attoptions.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "miscadmin.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "catalog/pg_namespace.h"
#include "utils/guc.h"

#include "catalog/binary_upgrade.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_class.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "nodes/makefuncs.h"
#include "storage/lock.h"

#include "catalog/pg_am_d.h"
#include "commands/vacuum.h"
#include "funcapi.h"
#include "storage/bufmgr.h"

#include "libpq/auth.h"
#include "utils/guc.h"
#include "utils/timestamp.h"

#include "utils/lsyscache.h"
#include "utils/regproc.h"

#include "access/toast_internals.h"
#include "access/toast_hook.h"
#include "utils/elog.h"
#include "pg_toaster.h"
#include "pg_toastrel.h"
#include "utils/varlena.h"
#include "varatt_custom.h"
#include "toastapi_internals.h"

/*
CREATE FUNCTION set_toaster(cstring, cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION add_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION drop_toaster(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION get_toaster(cstring, cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION list_toasters(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION list_toastrels(cstring)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C;

*/

extern Oid insert_toaster(const char *tsrname, const char *tsrhandler);

extern Oid insert_toastrel(Oid tsroid, Oid relid, Oid toastrelid, int16 attnum, int16 version, char opts, char flag);

extern void open_toastapi_index(Relation rel, LOCKMODE lock, Oid *idx_oid);

extern Datum add_toaster(PG_FUNCTION_ARGS);

extern Datum set_toaster(PG_FUNCTION_ARGS);

extern Datum drop_toaster(PG_FUNCTION_ARGS);

extern Datum get_toaster(PG_FUNCTION_ARGS);

extern Datum list_toasters(PG_FUNCTION_ARGS);

extern Datum list_toastrels(PG_FUNCTION_ARGS);

#endif
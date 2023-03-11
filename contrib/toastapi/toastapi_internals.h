#ifndef TOASTAPIINT_H
#define TOASTAPIINT_H

#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "commands/defrem.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
#include "access/xact.h"
#include "catalog/binary_upgrade.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "access/relation.h"
#include "access/attoptions.h"
#include "access/genam.h"
#include "toastapi.h"

extern Relation
get_rel_from_relname(text *relname_text, LOCKMODE lockmode, AclMode aclmode);

extern Datum attopts_get_toaster_opts(Oid relOid, char *attname, int attnum, char *optname);
extern Datum attopts_set_toaster_opts(Oid relOid, char *attname, char *optname, char *optval, int order);
extern Datum attopts_clear_toaster_opts(Oid relOid, char *attname, char *optname);

extern Oid lookup_toaster_handler_func(List *handler_name);
extern void create_pg_toaster(void);

#endif							/* TOASTAPIINT_H */
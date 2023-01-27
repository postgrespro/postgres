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
#include "access/genam.h"

#define TOASTER_HANDLEROID 8888

extern Relation get_rel_from_relname(text *relname_text, LOCKMODE lockmode, AclMode aclmode);

extern void load_toaster_cache(void);
extern void load_toastrel_cache(void);

extern Datum relopts_get_toaster_opts(Datum reloptions, Oid *relid, Oid *toasterid);
extern Datum relopts_set_toaster_opts(Datum reloptions, Oid relid, Oid toasterid);
extern Oid lookup_toaster_handler_func(List *handler_name);
extern void create_pg_toaster(void);
extern void create_pg_toastrel(void);

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

/*
extern void load_toaster_cache();
extern void load_toastrel_cache();
*/

extern Datum attopts_get_toaster_opts(Oid relOid, char *attname, int attnum, char *optname);
extern Datum attopts_set_toaster_opts(Oid relOid, char *attname, char *optname, char *optval, int order);

extern Oid lookup_toaster_handler_func(List *handler_name);
extern void create_pg_toaster(void);
extern void create_pg_toastrel(void);

static inline Datum set_numbered_att_opt_oid(Oid relid, char *optname, int len, char *nstr, Oid oid_val, char *attname, int order)
{
   char *tmp;
   char str[12];
   Datum d;
   int namelen = strlen(optname);
   int numlen = strlen(nstr);

  	tmp = palloc(namelen + numlen + 1);
	memcpy(tmp, optname, namelen);
	memcpy(tmp+namelen, nstr, numlen);
	tmp[namelen + numlen] = '\0';
	numlen = pg_ltoa(oid_val, str);
	Assert(numlen!=0);
	d = attopts_set_toaster_opts(relid, attname, tmp, str, order);
	pfree(tmp);
   return d;
}

#endif							/* TOASTAPIINT_H */
#ifndef ATTOPTIONS_H
#define ATTOPTIONS_H

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

extern Datum relopts_get_toaster_opts(Datum reloptions, Oid *relid, Oid *toasterid);
extern Datum relopts_set_toaster_opts(Datum reloptions, Oid relid, Oid toasterid);
extern Datum attopts_get_toaster_opts(Oid relOid, char *attname, int attnum, char *optname);
extern Datum attopts_set_toaster_opts(Oid relOid, char *attname, char *optname, char *optval, int order);

static inline Datum set_complex_att_opt(Oid relid, char *optname, char *nstr, char *val, char *attname, int order)
{
   char *tmp;
   Datum d;
   int namelen = strlen(optname);
   int numlen = strlen(nstr);

   tmp = palloc(namelen + numlen + 1);
	memcpy(tmp, optname, namelen);
	memcpy(tmp+namelen, nstr, numlen);
	tmp[namelen + numlen] = '\0';
	d = attopts_set_toaster_opts(relid, attname, tmp, val, order);
	pfree(tmp);
   return d;
}

static inline Datum get_complex_att_opt(Oid relid, char *optname, char *addstr, int addstrlen, int attnum)
{
   char *tmp;
   Datum d;
   int namelen = strlen(optname);
   int addlen = addstrlen;

   if(addlen < 0)
      addlen = strlen(addstr);

   tmp = palloc(namelen + addlen + 1);
	memcpy(tmp, optname, namelen);
	memcpy(tmp+namelen, addstr, addlen);
	tmp[namelen + addlen] = '\0';
	d = attopts_get_toaster_opts(relid, "", attnum, tmp);
	pfree(tmp);
   return d;
}

#endif /* ATTOPTIONS_H */
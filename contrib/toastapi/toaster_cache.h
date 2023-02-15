#ifndef TOASTERCACHE_H
#define TOASTERCACHE_H

#include "toastapi.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "access/heapam.h"
#include "access/xact.h"
#include "storage/lock.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "utils/memutils.h"
#include "utils/fmgroids.h"
#include "utils/regproc.h"
#include "nodes/nodes.h"
#include "pg_toaster.h"
#include "pg_toastrel.h"
#include "toastapi_internals.h"

typedef struct ToasterCacheEntry
{
	Oid			toasterOid;
	TsrRoutine *routine;
} ToasterCacheEntry;

static List	*ToasterCache = NIL;

typedef struct ToastrelCacheEntry
{
	Oid 		relid;
	int16 	attnum;
} ToastrelCacheEntry;

static List	*ToastrelCache = NIL;

extern Oid cache_pg_toaster();

#endif
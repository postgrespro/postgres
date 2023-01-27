/*-------------------------------------------------------------------------
 *
 * toastapi.c
 *		Pluggable TOAST API
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/toastapi/toastapi.c
 *
 *-------------------------------------------------------------------------
 */

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
#include "toastapi_sqlfuncs.h"

PG_MODULE_MAGIC;

/* Original Hook */
/*
typedef Datum (*Toast_Init_hook_type) (Oid reloid, Datum reloptions, int attnum, LOCKMODE lockmode,
						   bool check, Oid OIDOldToast);
typedef Datum (*Toast_Toast_hook_type) (ToastTupleContext *ttc, int attribute, int maxDataLen,
						int options);
typedef Datum (*Toast_Detoast_hook_type) (Oid relid, Datum toast_ptr,
											 int offset, int length);
*/

static Toastapi_init_hook_type toastapi_init_hook = NULL;
static Toastapi_toast_hook_type toastapi_toast_hook = NULL;
static Toastapi_detoast_hook_type toastapi_detoast_hook = NULL;
static Toastapi_size_hook_type toastapi_size_hook = NULL;

static Datum toastapi_init (Oid reloid, Oid toastOid, Oid toastIdxOid, Datum reloptions, int attnum, LOCKMODE lockmode,
						   bool check, Oid OIDOldToast)
{
   Datum result = (Datum) 0;
   elog(NOTICE, "toastapi_init hook");
   return result;
}

static Datum toastapi_toast (ToastTupleContext *ttc, int attribute, int maxDataLen,
						int options)
{
   Datum result = (Datum) 0;
   elog(NOTICE, "toastapi_toast hook");
   return result;
}

static Size toastapi_size (uint8 tag)
{
	return (tag) == VARTAG_CUSTOM ? offsetof(varatt_custom, va_toasterdata)	: 0;
}

static Datum toastapi_detoast (Oid relid, Datum toast_ptr,
											 int offset, int length)
{
	struct varlena *value;
	Datum result = toast_ptr;

   elog(NOTICE, "toastapi_detoast hook");
	value = (struct varlena *) DatumGetPointer(toast_ptr);
	if(VARATT_IS_EXTERNAL_ONDISK(value))
	{
		elog(NOTICE, "external tp");
	}
	if(VARATT_IS_CUSTOM(value))
	{
		Oid	toasterid = VARATT_CUSTOM_GET_TOASTERID(value);
		TsrRoutine *toaster = SearchTsrCache(toasterid);
		
		elog(NOTICE, "custom tp");
		return toaster->detoast(PointerGetDatum(value), 0, -1);
	}

   return result;
}

void _PG_init(void)
{
	create_pg_toaster();
	create_pg_toastrel();

   toastapi_init_hook = Toastapi_init_hook;
   toastapi_toast_hook = Toastapi_toast_hook;
   toastapi_detoast_hook = Toastapi_detoast_hook;
   toastapi_size_hook = Toastapi_size_hook;


   Toastapi_init_hook = toastapi_init;
   Toastapi_toast_hook = toastapi_toast;
   Toastapi_detoast_hook = toastapi_detoast;
   Toastapi_size_hook = toastapi_size;
}

void _PG_fini(void)
{
   Toastapi_init_hook = toastapi_init_hook;
   Toastapi_toast_hook = toastapi_toast_hook;
   Toastapi_detoast_hook = toastapi_detoast_hook;
}
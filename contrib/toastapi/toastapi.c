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
static Toastapi_copy_hook_type toastapi_copy_hook = NULL;
static Toastapi_update_hook_type toastapi_update_hook = NULL;
static Toastapi_delete_hook_type toastapi_delete_hook = NULL;

static Datum toastapi_init (Oid reloid, Datum reloptions, int attnum, LOCKMODE lockmode,
						   bool check, Oid OIDOldToast)
{
   Datum result = (Datum) 0;
	FormData_pg_attribute *pg_attr;
	Datum d;
	TsrRoutine *toaster = NULL;
	Relation rel;
	int ntoasters = 0;

	rel = table_open(reloid, RowExclusiveLock);
	pg_attr = &rel->rd_att->attrs[attnum];

	d = attopts_get_toaster_opts(reloid, NameStr(pg_attr->attname), attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
		return (Datum) 0;
	else
		ntoasters = atoi(DatumGetCString(d));

	{
		int len = 0;
		char str[12];

		len = pg_ltoa(ntoasters, str);
		d = get_complex_att_opt(RelationGetRelid(rel), ATT_HANDLER_NAME, str, len, attnum);
	}

	toaster = GetTsrRoutine(atoi(DatumGetCString(d)));
	if(toaster == NULL)
	{
		elog(NOTICE, "No routine found");
		return (Datum) 0;
	}

	result = toaster->init(rel,
									atoi(DatumGetCString(d)),
									reloptions,
									attnum,
									lockmode,
									check,
									OIDOldToast);
	table_close(rel, RowExclusiveLock);
   return result;
}

static Datum toastapi_toast (ToastTupleContext *ttc, int attribute, int maxDataLen,
						int options)
{
   Datum result = (Datum) 0;
	Datum	   *value = &ttc->ttc_values[attribute];
	Datum		old_value = *value;
	ToastAttrInfo *attr = &ttc->ttc_attr[attribute];
	Datum d;
	Relation rel;
	TsrRoutine *toaster = NULL;
	char *ntoasters_str;
//	int ntoasters = 0;
//	int len;
	Oid tsrhandler = InvalidOid;

	rel = table_open(RelationGetRelid(ttc->ttc_rel), RowExclusiveLock);

	d = attopts_get_toaster_opts(RelationGetRelid(ttc->ttc_rel), "", attribute+1, ATT_NTOASTERS_NAME);
	
	if(d == (Datum) 0)
	{
		result = toast_save_datum(ttc->ttc_rel, old_value, attr->tai_oldexternal,
			options);

		table_close(rel, RowExclusiveLock);

		return result;
	}

	ntoasters_str = DatumGetCString(d);
//	ntoasters = atoi(ntoasters_str);
//	len = pg_ltoa(ntoasters, str);

	d = get_complex_att_opt(RelationGetRelid(rel), ATT_HANDLER_NAME, ntoasters_str, strlen(ntoasters_str), attribute+1);

	if(d == (Datum) 0)
	{
		table_close(rel, RowExclusiveLock);
		return *value;
	}
	else
	{
		tsrhandler = atoi(DatumGetCString(d));
		toaster = GetTsrRoutine(tsrhandler);
	}

	d = get_complex_att_opt(RelationGetRelid(rel), ATT_TOASTREL_NAME, ntoasters_str, strlen(ntoasters_str), attribute+1);

	table_close(rel, RowExclusiveLock);

	if(d == (Datum) 0)
	{
		toastapi_init(RelationGetRelid(ttc->ttc_rel), (Datum) 0, attribute+1, RowExclusiveLock, false, InvalidOid);
	}

	if(toaster != NULL)
	{
		result = toaster->toast(ttc->ttc_rel,
										tsrhandler,
										old_value,
										PointerGetDatum(attr->tai_oldexternal),
										attribute+1,
										maxDataLen, options);
	}
	else
	{
		return *value;
	}
	
	return result;
}

static Size toastapi_size (uint8 tag, const void *ptr)
{
	return (tag) == VARTAG_CUSTOM ? offsetof(varatt_custom, va_toasterdata) + VARATT_CUSTOM_GET_DATA_SIZE(ptr) : 0;
}

static Datum toastapi_detoast (Oid relid, Datum toast_ptr,
											 int offset, int length)
{
	struct varlena *value;
	Datum result = toast_ptr;

	value = (struct varlena *) DatumGetPointer(toast_ptr);
	if(VARATT_IS_EXTERNAL_ONDISK(value))
	{
		elog(NOTICE, "Detoast hook called for regular External TOAST pointer");
	}
	if(VARATT_IS_CUSTOM(value))
	{
		TsrRoutine *toaster = NULL;
		Oid	toasterid = VARATT_CUSTOM_GET_TOASTERID(value);
		toaster = GetTsrRoutine(toasterid);

		result = toaster->detoast(toast_ptr, offset, length);
	}

   return result;
}

static Datum toastapi_update (Relation rel,
												  int options,
												  Datum old_value,
												  Datum new_value,
												  int attnum)
{
	Datum res = (Datum) 0;
	return res;
}

static Datum toastapi_copy (Relation rel,
									Datum value,
									bool is_speculative,
									int attnum)
{
	Datum res = (Datum) 0;
	return res;
}

static Datum toastapi_delete (Relation rel,
										Datum value,
										bool is_speculative,
										int attnum)
{
	Datum res = (Datum) 0;
	return res;
}

bool get_toast_params(Oid relid, int attnum, int *ntoasters, Oid *toasteroid, Oid *toastrelid, Oid *handlerid)
{
	Datum d;
	char str[12];
	char *ntoasters_str;
	int len = 0;
	bool all_found_ind = true;

	*ntoasters = 0;
	*toasteroid = InvalidOid;
	*toastrelid = InvalidOid;
	*handlerid = InvalidOid;
	str[0] = '\0';

	d = attopts_get_toaster_opts(relid, "", attnum, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
		all_found_ind = false;
	else
	{
		ntoasters_str = DatumGetCString(d);
		*ntoasters = atoi(ntoasters_str);
		len = pg_ltoa(*ntoasters, str);
	}

	d = get_complex_att_opt(relid, ATT_HANDLER_NAME, str, len, attnum);
	if(d == (Datum) 0)
		all_found_ind = false;
	else
		*handlerid = atoi(DatumGetCString(d));

	d = get_complex_att_opt(relid, ATT_TOASTER_NAME, str, len, attnum);
	if(d == (Datum) 0)
		all_found_ind = false;
	else
		*toasteroid = atoi(DatumGetCString(d));

	d = get_complex_att_opt(relid, ATT_TOASTREL_NAME, str, len, attnum);
	if(d == (Datum) 0)
		all_found_ind = false;
	else
		*toastrelid = atoi(DatumGetCString(d));

	return all_found_ind;
}

void _PG_init(void)
{
	create_pg_toaster();
	// create_pg_toastrel();
   toastapi_init_hook = Toastapi_init_hook;
   toastapi_toast_hook = Toastapi_toast_hook;
   toastapi_detoast_hook = Toastapi_detoast_hook;
   toastapi_size_hook = Toastapi_size_hook;
	toastapi_copy_hook = Toastapi_copy_hook;
	toastapi_update_hook = Toastapi_update_hook;
	toastapi_delete_hook = Toastapi_delete_hook;

   Toastapi_init_hook = toastapi_init;
   Toastapi_toast_hook = toastapi_toast;
   Toastapi_detoast_hook = toastapi_detoast;
   Toastapi_size_hook = toastapi_size;
	Toastapi_copy_hook = toastapi_copy;
	Toastapi_update_hook = toastapi_update;
	Toastapi_delete_hook = toastapi_delete;
}

void _PG_fini(void)
{
   Toastapi_init_hook = toastapi_init_hook;
   Toastapi_toast_hook = toastapi_toast_hook;
   Toastapi_detoast_hook = toastapi_detoast_hook;
	Toastapi_copy_hook = toastapi_copy_hook;
	Toastapi_update_hook = toastapi_update_hook;
	Toastapi_delete_hook = toastapi_delete_hook;
	Toastapi_size_hook = toastapi_size_hook;
}
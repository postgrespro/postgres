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
	{
		ntoasters = 0;
		elog(NOTICE, "No toaster assigned to table");
		return (Datum) 0;
	}
	else
	{
		ntoasters = atoi(DatumGetCString(d));
	}

	{
		char *handler;
		int len = 0;
		char str[12];

		len = pg_ltoa(ntoasters, str);
		handler = palloc(strlen(ATT_HANDLER_NAME) + len + 1);
		
		memcpy(handler, ATT_HANDLER_NAME, strlen(ATT_HANDLER_NAME));
		memcpy(handler+strlen(ATT_HANDLER_NAME), str, len);
		
		handler[strlen(ATT_HANDLER_NAME) + len] = '\0';
		d = attopts_get_toaster_opts(RelationGetRelid(rel), "", attnum, handler);
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
	FormData_pg_attribute *pg_attr = &ttc->ttc_rel->rd_att->attrs[attribute];
	Datum d;
	Relation rel;
	TsrRoutine *toaster = NULL;
	char *ntoasters_str;
	char *tmp;
	int ntoasters = 0;
	int len;
	char str[12];
	Oid tsrhandler = InvalidOid;

	rel = table_open(RelationGetRelid(ttc->ttc_rel), RowExclusiveLock);

	d = attopts_get_toaster_opts(RelationGetRelid(ttc->ttc_rel), "", attribute+1, ATT_NTOASTERS_NAME);
	if(d == (Datum) 0)
	{
		elog(NOTICE, "No Toasters for rel <%u>", RelationGetRelid(ttc->ttc_rel));
		table_close(rel, RowExclusiveLock);
		return *value;
	}

	ntoasters_str = DatumGetCString(d);
	ntoasters = atoi(ntoasters_str);
	len = pg_ltoa(ntoasters, str);

	tmp = palloc(strlen(ATT_HANDLER_NAME) + len + 1);
	memcpy(tmp, ATT_HANDLER_NAME, strlen(ATT_HANDLER_NAME));
	memcpy(tmp + strlen(ATT_HANDLER_NAME), str, len);
	tmp[strlen(ATT_HANDLER_NAME) + strlen(str)] = '\0';

	d = attopts_get_toaster_opts(RelationGetRelid(ttc->ttc_rel), NameStr(pg_attr->attname), attribute+1, tmp);
		
	if(d == (Datum) 0)
	{
		elog(NOTICE, "No Toasters for rel <%u>", RelationGetRelid(ttc->ttc_rel));
		table_close(rel, RowExclusiveLock);
		return *value;
	}
	else
	{
		tsrhandler = atoi(DatumGetCString(d));
		toaster = GetTsrRoutine(tsrhandler);
	}

	tmp = palloc(strlen(ATT_TOASTREL_NAME) + len + 1);
	memcpy(tmp, ATT_TOASTREL_NAME, strlen(ATT_TOASTREL_NAME));
	memcpy(tmp + strlen(ATT_TOASTREL_NAME), str, len);
	tmp[strlen(ATT_TOASTREL_NAME) + strlen(ntoasters_str)] = '\0';
	d = attopts_get_toaster_opts(RelationGetRelid(ttc->ttc_rel), NameStr(pg_attr->attname), attribute+1, tmp);

	table_close(rel, RowExclusiveLock);

	if(d == (Datum) 0)
	{
		toastapi_init(RelationGetRelid(ttc->ttc_rel), (Datum) 0, attribute+1, RowExclusiveLock, false, InvalidOid);
	}
	pfree(tmp);

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
		elog(NOTICE, "No routine found");
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

		return toaster->detoast(toast_ptr, offset, length);
	}

   return result;
}

bool get_toast_params(Oid relid, int attnum, int *ntoasters, Oid *toasteroid, Oid *toastrelid, Oid *handlerid)
{
	Datum d;
	char str[12];
	char *tmp;
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

	tmp = palloc(strlen(ATT_HANDLER_NAME) + len + 1);
	memcpy(tmp, ATT_HANDLER_NAME, strlen(ATT_HANDLER_NAME));
	memcpy(tmp + strlen(ATT_HANDLER_NAME), str, len);
	tmp[strlen(ATT_HANDLER_NAME) + strlen(str)] = '\0';

	d = attopts_get_toaster_opts(relid, "", attnum, tmp);
		
	if(d == (Datum) 0)
		all_found_ind = false;
	else
		*handlerid = atoi(DatumGetCString(d));

	tmp = palloc(strlen(ATT_TOASTER_NAME) + len + 1);
	memcpy(tmp, ATT_TOASTER_NAME, strlen(ATT_TOASTER_NAME));
	memcpy(tmp + strlen(ATT_TOASTER_NAME), str, len);
	tmp[strlen(ATT_TOASTER_NAME) + len] = '\0';
	d = attopts_get_toaster_opts(relid, "", attnum, tmp);

	if(d == (Datum) 0)
		all_found_ind = false;
	else
		*toasteroid = atoi(DatumGetCString(d));

	tmp = palloc(strlen(ATT_TOASTREL_NAME) + len + 1);
	memcpy(tmp, ATT_TOASTREL_NAME, strlen(ATT_TOASTREL_NAME));
	memcpy(tmp + strlen(ATT_TOASTREL_NAME), str, len);
	tmp[strlen(ATT_TOASTREL_NAME) + len] = '\0';
	d = attopts_get_toaster_opts(relid, "", attnum, tmp);

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
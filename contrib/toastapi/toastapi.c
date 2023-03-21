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

#include "access/detoast.h"
#include "access/toast_internals.h"
#include "access/toast_extended.h"
#include "access/toast_hook.h"
#include "utils/elog.h"
#include "pg_toaster.h"
#include "pg_toastrel.h"
#include "utils/varlena.h"
#include "varatt_custom.h"
#include "toastapi_internals.h"
#include "toastapi_sqlfuncs.h"

PG_MODULE_MAGIC;

static Toastapi_toast_hook_type toastapi_toast_hook = NULL;
static Toastapi_detoast_hook_type toastapi_detoast_hook = NULL;
static Toastapi_size_hook_type toastapi_size_hook = NULL;
static Toastapi_copy_hook_type toastapi_copy_hook = NULL;
static Toastapi_update_hook_type toastapi_update_hook = NULL;
static Toastapi_delete_hook_type toastapi_delete_hook = NULL;
static Toastapi_vtable_hook_type toastapi_vtable_hook = NULL;

static TsrRoutine *
get_toaster_for_attr(Relation rel, int attnum, ToastAttributes tattrs)
{
	TsrRoutine *toaster;
	Datum		tsrhandler_str;
	Oid			tsrhandler;

	tsrhandler_str = attopts_get_toaster_opts(RelationGetRelid(rel), "",
											  attnum, ATT_HANDLER_NAME);

	if (tsrhandler_str == (Datum) 0)
		return NULL;

	tsrhandler = atoi(DatumGetCString(tsrhandler_str));

	if (!OidIsValid(tsrhandler))
		return NULL;

	toaster = SearchTsrHandlerCache(tsrhandler); //GetTsrRoutine(tsrhandler);

	if (tattrs)
	{
		tattrs->toasteroid = InvalidOid;
		tattrs->attnum = attnum;
		tattrs->toasthandleroid = tsrhandler;
		tattrs->toaster = toaster;
		tattrs->toastreloid = rel->rd_rel->reltoastrelid;
	}

	return toaster;
}

static Datum
toastapi_toast(ToastTupleContext *ttc, int attribute, int maxDataLen,
			   int options)
{
	Relation	rel = ttc->ttc_rel;
	Datum		old_value = ttc->ttc_values[attribute];
	ToastAttributesData tattrs;
	TsrRoutine *toaster = get_toaster_for_attr(rel, attribute + 1, &tattrs);

	if (!toaster)
		return (Datum) 0;

	if (!OidIsValid(rel->rd_rel->reltoastrelid))
		elog(ERROR, "toast relation is missing for toasted attribute %d of relation %u",
			 attribute, RelationGetRelid(rel));

	tattrs.attnum = attribute + 1;
	return toaster->toast(rel,
						  old_value,
						  old_value, // PointerGetDatum(attr->tai_oldexternal),
						  maxDataLen, options, &tattrs);
}

static Size toastapi_size (uint8 tag, const void *ptr)
{
	return offsetof(varatt_custom, va_toasterdata) + VARATT_CUSTOM_GET_DATA_SIZE(ptr);
}
/*
static Size toastapi_size (uint8 tag, const void *ptr)
{
	return (tag) == VARTAG_CUSTOM ? offsetof(varatt_custom, va_toasterdata) + VARATT_CUSTOM_GET_DATA_SIZE(ptr) : sizeof(ptr);
}
*/

static TsrRoutine *
get_toaster_for_ptr(Datum toast_ptr, ToastAttributes tattrs)
{
	struct varlena *custom_toast_ptr = (struct varlena *) DatumGetPointer(toast_ptr);
	Oid			toasterhandleroid;
	TsrRoutine *toaster;

	Assert(VARATT_IS_CUSTOM(custom_toast_ptr));

	/* FIXME handler oid stored instead of toaster oid */
	toasterhandleroid = VARATT_CUSTOM_GET_TOASTERID(custom_toast_ptr);

	toaster = SearchTsrHandlerCache(toasterhandleroid); // GetTsrRoutine(toasterhandleroid);

	if (tattrs)
	{
		tattrs->ntoasters = 0;
		tattrs->toasteroid = InvalidOid;
		tattrs->toastreloid = InvalidOid;
		tattrs->toasthandleroid = toasterhandleroid;
		tattrs->toaster = toaster;
		/* tattrs->attnum is filled by caller */
	}

	return toaster;
}

static Datum
toastapi_detoast(Oid relid, Datum toast_ptr, int offset, int length)
{
	ToastAttributesData tattrs;
	TsrRoutine *toaster;

#if 0 /* TODO */
	if (VARATT_IS_EXTERNAL_ONDISK(DatumGetPointer(toast_ptr)))
		return custom_detoast(toast_ptr, offset, length);
#endif

	toaster = get_toaster_for_ptr(toast_ptr, &tattrs);

	tattrs.attnum = -1;

	return toaster->detoast(toast_ptr, offset, length, &tattrs);
}

static Datum
toastapi_update(Relation rel, int options, Datum new_value, Datum old_value,
				int attnum)
{
	struct varlena *new_val = (struct varlena *) DatumGetPointer(new_value);
	struct varlena *old_val = (struct varlena *) DatumGetPointer(old_value);
	ToastAttributesData tattrs;
	TsrRoutine *toaster;
	Oid			old_toasterid;
	Oid			new_toasterid;

	Assert(VARATT_IS_CUSTOM(new_val) && VARATT_IS_CUSTOM(old_val));

	old_toasterid = VARATT_CUSTOM_GET_TOASTERID(old_val);
	new_toasterid = VARATT_CUSTOM_GET_TOASTERID(new_val);

	if (new_toasterid != old_toasterid)
		return (Datum) 0;

	toaster = get_toaster_for_ptr(new_value, &tattrs);

	if (!toaster->update_toast)
		return (Datum) 0;

	tattrs.attnum = attnum;
	tattrs.toasthandleroid = new_toasterid;

	return toaster->update_toast(rel,
								 new_value, old_value,
								 options, &tattrs);
}

static Datum
toastapi_copy(Relation rel,
			  Datum copy_value,
			  bool is_speculative,
			  int attnum)
{
	ToastAttributesData tattrs;
	TsrRoutine *toaster = get_toaster_for_ptr(copy_value, &tattrs);

	if (!toaster->copy_toast)
		return (Datum) 0;

	tattrs.attnum = attnum;

	return toaster->copy_toast(rel,
							   copy_value, 0, &tattrs);
}

static void
toastapi_delete(Relation rel,
				Datum del_value,
				bool is_speculative,
				int attnum)
{
	ToastAttributesData tattrs;
	TsrRoutine *toaster = get_toaster_for_ptr(del_value, &tattrs);

	if (!toaster->deltoast)
		return;

	tattrs.toastreloid = rel->rd_rel->reltoastrelid;
	tattrs.attnum = attnum;

	toaster->deltoast(rel, del_value, is_speculative, &tattrs);
}

static void *
toastapi_vtable(Datum value)
{
	TsrRoutine *toaster = get_toaster_for_ptr(value, NULL);

	return toaster->get_vtable ? toaster->get_vtable(value) : NULL;
}

void _PG_init(void)
{
	toastapi_toast_hook = Toastapi_toast_hook;
	toastapi_detoast_hook = Toastapi_detoast_hook;
	toastapi_size_hook = Toastapi_size_hook;
	toastapi_copy_hook = Toastapi_copy_hook;
	toastapi_update_hook = Toastapi_update_hook;
	toastapi_delete_hook = Toastapi_delete_hook;
	toastapi_vtable_hook = Toastapi_vtable_hook;

	Toastapi_toast_hook = toastapi_toast;
	Toastapi_detoast_hook = toastapi_detoast;
	Toastapi_size_hook = toastapi_size;
	Toastapi_copy_hook = toastapi_copy;
	Toastapi_update_hook = toastapi_update;
	Toastapi_delete_hook = toastapi_delete;
	Toastapi_vtable_hook = toastapi_vtable;
}

void _PG_fini(void)
{
	Toastapi_toast_hook = toastapi_toast_hook;
	Toastapi_detoast_hook = toastapi_detoast_hook;
	Toastapi_copy_hook = toastapi_copy_hook;
	Toastapi_update_hook = toastapi_update_hook;
	Toastapi_delete_hook = toastapi_delete_hook;
	Toastapi_size_hook = toastapi_size_hook;
	Toastapi_vtable_hook = toastapi_vtable_hook;
}

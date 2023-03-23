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
#include "fmgr.h"
#include "access/toast_hook.h"

#include "toastapi.h"
#include "toastapi_internals.h"

PG_MODULE_MAGIC;

static Toastapi_toast_hook_type toastapi_toast_hook = NULL;
static Toastapi_detoast_hook_type toastapi_detoast_hook = NULL;
static Toastapi_size_hook_type toastapi_size_hook = NULL;
static Toastapi_copy_hook_type toastapi_copy_hook = NULL;
static Toastapi_update_hook_type toastapi_update_hook = NULL;
static Toastapi_delete_hook_type toastapi_delete_hook = NULL;
static Toastapi_vtable_hook_type toastapi_vtable_hook = NULL;

typedef struct RelToastCache
{
	TsrRoutine	routine;
	Oid			handleroid;
	/* char toaster_options[FLEXIBLE_ARRAY_MEMBER]; */
} RelToastCache;

static RelToastCache *
init_toaster_cache(Relation rel, Oid handleroid)
{
	TsrRoutine *toaster = SearchTsrHandlerCache(handleroid);
	RelToastCache *cache = RelationToastCacheAlloc(rel, sizeof(RelToastCache));

	memcpy(&cache->routine, toaster, sizeof(*toaster));
	cache->handleroid = handleroid;

	return cache;
}

static RelToastCache *
get_toaster_cacher_for_attr(Relation rel, int attnum)
{
	void	  **rd_toastcache = RelationGetToastCache(rel);
	RelToastCache *cache = rd_toastcache[attnum];

	if (!cache)
	{
		Oid			tsrhandler;
		char	   *tsrhandler_str =
			attopts_get_toaster_opts(rel, attnum + 1, ATT_HANDLER_NAME);

		if (!tsrhandler_str)
			return NULL;

		tsrhandler = atoi(tsrhandler_str);

		if (!OidIsValid(tsrhandler))
			return NULL;

		rd_toastcache[attnum] = cache = init_toaster_cache(rel, tsrhandler);
	}

	return cache;
}

static TsrRoutine *
get_toaster_for_attr(Relation rel, int attnum, ToastAttributes tattrs)
{
	RelToastCache *cache = get_toaster_cacher_for_attr(rel, attnum);

	if (!cache)
		return NULL;

	if (tattrs)
	{
		tattrs->toasteroid = InvalidOid;
		tattrs->attnum = attnum + 1;
		tattrs->toasthandleroid = cache->handleroid;
		tattrs->toaster = &cache->routine;
		tattrs->toastreloid = rel->rd_rel->reltoastrelid;
	}

	return &cache->routine;
}

static Datum
toastapi_toast(ToastTupleContext *ttc, int attnum, int maxDataLen,
			   int options)
{
	Relation	rel = ttc->ttc_rel;
	Datum		old_value = ttc->ttc_values[attnum];
	ToastAttributesData tattrs;
	TsrRoutine *toaster = get_toaster_for_attr(rel, attnum, &tattrs);

	if (!toaster)
		return (Datum) 0;

	if (!OidIsValid(rel->rd_rel->reltoastrelid))
		elog(ERROR, "toast relation is missing for toasted attribute %d of relation %u",
			 attnum, RelationGetRelid(rel));

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
get_toaster_for_ptr(Relation rel, int attnum, Datum toast_ptr, ToastAttributes tattrs)
{
	struct varlena *custom_toast_ptr = (struct varlena *) DatumGetPointer(toast_ptr);
	Oid			toaster_handler_oid;
	TsrRoutine *toaster = NULL;
	RelToastCache *cache;

	Assert(VARATT_IS_CUSTOM(custom_toast_ptr));

	/* FIXME handler oid stored instead of toaster oid */
	toaster_handler_oid = VARATT_CUSTOM_GET_TOASTERID(custom_toast_ptr);

	if (rel && attnum >= 0 &&
		(cache = get_toaster_cacher_for_attr(rel, attnum)) &&
		cache->handleroid == toaster_handler_oid)
		toaster = &cache->routine;
	else
		toaster = SearchTsrHandlerCache(toaster_handler_oid);

	if (tattrs)
	{
		tattrs->ntoasters = 0;
		tattrs->toasteroid = InvalidOid;
		tattrs->toastreloid = rel ? rel->rd_rel->reltoastrelid : InvalidOid;
		tattrs->toasthandleroid = toaster_handler_oid;
		tattrs->toaster = toaster;
		tattrs->attnum = attnum + 1;
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

	toaster = get_toaster_for_ptr(NULL, -1, toast_ptr, &tattrs);

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

	toaster = get_toaster_for_ptr(rel, attnum, new_value, &tattrs);

	if (!toaster->update_toast)
		return (Datum) 0;

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
	TsrRoutine *toaster = get_toaster_for_ptr(rel, attnum, copy_value, &tattrs);

	if (!toaster->copy_toast)
		return (Datum) 0;

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
	TsrRoutine *toaster = get_toaster_for_ptr(rel, attnum, del_value, &tattrs);

	if (!toaster->deltoast)
		return;

	toaster->deltoast(rel, del_value, is_speculative, &tattrs);
}

static void *
toastapi_vtable(Datum value)
{
	TsrRoutine *toaster = get_toaster_for_ptr(NULL, -1, value, NULL);

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

/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Dummy toaster - sample toaster for Toaster API.
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/dummy_toaster/dummy_toaster.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"
#include "access/toasterapi.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "catalog/pg_toaster.h"
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

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(dummy_toaster_handler);

#define MAX_DUMMY_CHUNK_SIZE 1024

/*
 * Dummy Detoast function, receives single varatt_custom pointer,
 * detoasts it to varlena.
 *
 */
static Datum
dummy_detoast(Datum toast_ptr,
			 int offset, int length)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	struct varlena *result;

	Assert(VARATT_IS_EXTERNAL(attr));
	Assert(VARATT_IS_CUSTOM(attr));

	result = palloc(VARATT_CUSTOM_GET_DATA_RAW_SIZE(attr));
	SET_VARSIZE(result, VARATT_CUSTOM_GET_DATA_RAW_SIZE(attr));
	memcpy(VARDATA(result), VARATT_CUSTOM_GET_DATA(attr),
		   VARATT_CUSTOM_GET_DATA_RAW_SIZE(attr) - VARHDRSZ);

	return PointerGetDatum(result);
}

/*
 * Dummy Toast function, receives varlena pointer, creates single varatt_custom
 * varlena size is limited to 1024 bytes
 */
static Datum
dummy_toast(Relation toast_rel, Oid toasterid,
		   Datum value, Datum oldvalue,
		   int max_inline_size,  int options)
{
	struct varlena			*attr;
	struct varlena			*result;
	int	len;
	attr = (struct varlena*)DatumGetPointer(value); //pg_detoast_datum((struct varlena*)DatumGetPointer(value));

	if(VARSIZE_ANY_EXHDR(attr) > MAX_DUMMY_CHUNK_SIZE)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds MAX_DUMMY_CHUNK_SIZE <%d>",
								 (int)VARSIZE_ANY_EXHDR(attr), MAX_DUMMY_CHUNK_SIZE)));

	}

	len = VARATT_CUSTOM_SIZE(VARSIZE_ANY_EXHDR(attr));

	if (max_inline_size > 0 && len > max_inline_size)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds max inline size <%d>",
								 len, max_inline_size)));
	}

	result = palloc(len);

	SET_VARTAG_EXTERNAL(result, VARTAG_CUSTOM);
	VARATT_CUSTOM_SET_DATA_RAW_SIZE(result, VARSIZE_ANY_EXHDR(attr) + VARHDRSZ);
	VARATT_CUSTOM_SET_DATA_SIZE(result, len);
	VARATT_CUSTOM_SET_TOASTERID(result, toasterid);

	memcpy(VARATT_CUSTOM_GET_DATA(result), VARDATA_ANY(attr),
		   VARSIZE_ANY_EXHDR(attr));

	if ((char*)attr != DatumGetPointer(value))
		pfree(attr);

	return PointerGetDatum(result);
}

/*
 * Dummy delete function
 */
static void
dummy_delete(Datum value, bool is_speculative)
{
}

/*
 * Dummy Validate, always returns True
 *
 */
static bool
dummy_toaster_validate(Oid typeoid, char storage, char compression,
                                        Oid amoid, bool false_ok)
{
	bool result = true;
	return result;
}

/*
 * Dummy validation function, always returns TRUE
 */
static void
dummy_toast_init(Relation rel, Oid toastoid, Oid toastindexoid, Datum reloptions, LOCKMODE lockmode,
						   bool check, Oid OIDOldToast)
{
}

Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine  *tsr = makeNode(TsrRoutine);
	tsr->init = dummy_toast_init;
	tsr->toast = dummy_toast;
	tsr->update_toast = NULL;
	tsr->copy_toast = NULL;
	tsr->detoast = dummy_detoast;
	tsr->deltoast = dummy_delete;
	tsr->get_vtable = NULL;
	tsr->toastervalidate = dummy_toaster_validate;

	PG_RETURN_POINTER(tsr);
}

/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Dummy toaster utilities.
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
#include "access/detoast.h"
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
#include "storage/lock.h"
#include "utils/rel.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/toast_internals.h"
#include "access/heapam.h"

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(dummy_toaster_handler);

#define MAX_DUMMY_CHUNK_SIZE 1024

/*
 * Dummy Detoast function, receives single varatt_custom pointer,
 * detoasts it to varlena.
 *
 */
static struct varlena*
dummyDetoast(Datum toast_ptr,
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

	return result;
}

/*
 * Dummy Toast function, receives varlena pointer, creates single varatt_custom
 * varlena size is limited to 1024 bytes
 */

static struct varlena*
dummyToast(Relation toast_rel,
					Datum value, Datum oldvalue,
					int max_inline_size)
{
	struct varlena			*attr;
	struct varatt_custom	*toast_pointer;
	struct varlena			*result;
	int	len;

	/* dummy: simplify work as possible */
	attr = pg_detoast_datum((struct varlena*)DatumGetPointer(value));

	if(VARSIZE_ANY_EXHDR(attr) > MAX_DUMMY_CHUNK_SIZE)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds MAX_DUMMY_CHUNK_SIZE <%d>",
								 (((varatt_custom *)(attr))->va_toasterdatalen),
								 MAX_DUMMY_CHUNK_SIZE)));

	}

	len = VARATT_CUSTOM_SIZE(VARSIZE_ANY_EXHDR(attr));
	result = palloc(len);
	SET_VARTAG_EXTERNAL(result, VARTAG_CUSTOM);
	Assert(VARATT_IS_EXTERNAL(result));
	Assert(VARATT_IS_CUSTOM(result));

	toast_pointer = VARATT_CUSTOM_GET_TOASTPOINTER(result);
	toast_pointer->va_rawsize = VARSIZE_ANY_EXHDR(attr) + VARHDRSZ;
	toast_pointer->va_toasterdatalen = len;
	toast_pointer->va_toasterid = get_toaster_oid("dummy_toaster", false);
	toast_pointer->va_version = 0xBADC0DED;

	memcpy(toast_pointer->va_toasterdata, VARDATA_ANY(attr),
		   VARSIZE_ANY_EXHDR(attr));

	if ((char*)attr != DatumGetPointer(value))
		pfree(attr);

	return result;
}

static void
dummyToastInit(Relation rel, Datum reloptions, LOCKMODE lockmode,
				 bool check, Oid OIDOldToast)
{
}

static void
dummyDelete(Datum value, bool is_speculative)
{
}

static bool
dummyToasterValidate(Oid typeoid,  char storage, char compression,
					 Oid amoid, bool false_ok)
{
	bool result = true;

	return result;
}


Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);
	tsrroutine->init = dummyToastInit;
	tsrroutine->toast = dummyToast;
	tsrroutine->detoast = dummyDetoast;
	tsrroutine->deltoast = dummyDelete;
	tsrroutine->get_vtable = NULL;
	tsrroutine->toastervalidate = dummyToasterValidate;
	PG_RETURN_POINTER(tsrroutine);
}

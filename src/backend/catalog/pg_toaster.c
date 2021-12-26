/*-------------------------------------------------------------------------
 *
 * pg_toaster.c
 *		PG_Toaster functions
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *		src/backend/catalog/pg_toaster.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/toasterapi.h"
#include "access/toast_internals.h"
#include "catalog/pg_am.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "utils/fmgrprotos.h"
#include "access/detoast.h"

static Datum
genericDetoast(Relation toast_rel, Datum toast_ptr, int offset, int length)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	struct varlena *result = 0;
	varatt_external toast_pointer;
		Relation	toastrel;

	Assert(VARATT_IS_EXTERNAL(attr));
	VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

	toastrel = table_open(toast_pointer.va_toastrelid, AccessShareLock);

	heap_fetch_toast_slice(toastrel, toast_pointer.va_valueid,
	toast_pointer.va_extinfo, offset, length, result);

	table_close(toastrel, AccessShareLock);

	return PointerGetDatum(result);
}

static Datum
genericToast(Relation toast_rel, Datum newvalue,
			 Datum oldvalue, int max_inline_size)
{
	struct varlena *new_attr = (struct varlena *) DatumGetPointer(newvalue);
	struct varlena *old_attr = (struct varlena *) DatumGetPointer(oldvalue);
	struct varlena *result = 0;

	if (VARATT_IS_EXTERNAL(new_attr))
	{
		result = (struct varlena *) DatumGetPointer( toast_save_datum(toast_rel, newvalue,
			old_attr, max_inline_size));
	}
	else
	{
		PG_RETURN_VOID();
	}

	return PointerGetDatum(result);
}

static Datum
genericDeleteToast(Relation rel, Datum toast_ptr)
{
	PG_RETURN_VOID();
}

static bool
genericToasterValidate(Oid typeoid, char storage, char compression,
					   Oid amoid, bool false_ok)
{
	/* generic toaster works for every type and access method */
	return true;
}

Datum
default_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);

	tsrroutine->toast = genericToast;
	tsrroutine->detoast = genericDetoast;
	tsrroutine->deltoast = genericDeleteToast;
	tsrroutine->get_vtable = NULL;
	tsrroutine->toastervalidate = genericToasterValidate;

	PG_RETURN_POINTER(tsrroutine);
}


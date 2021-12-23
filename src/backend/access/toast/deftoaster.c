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
#include "access/deftoaster.h"

#define GENERIC_TOASTER_MAGIC	0xf1f1f1f1

typedef struct GenericToastRoutine
{
	int32		magic;
} GenericToastRoutine;

extern bool toastrel_valueid_exists(Relation toastrel, Oid valueid);
extern bool toastid_valueid_exists(Oid toastrelid, Oid valueid);

extern Datum
toast_save_datum(Relation rel, Datum value,
				 struct varlena *oldexternal, int options);

extern void
heap_fetch_toast_slice(Relation toastrel, Oid valueid, int32 attrsize,
					   int32 sliceoffset, int32 slicelength,
					   struct varlena *result);

/*
 * Validate the generic options given to a FOREIGN DATA WRAPPER, SERVER,
 * USER MAPPING or FOREIGN TABLE that uses file_fdw.
 *
 * Raise an ERROR if the option or its value is considered invalid.
 */
Datum genericDetoast(Relation toast_rel,
								Datum toast_ptr,
								int offset, int length)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	struct varlena *result = 0;
    varatt_external toast_pointer;
	Relation	toastrel;

	Assert(VARATT_IS_EXTERNAL(attr));
	VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

	toastrel = table_open(toast_pointer.va_toastrelid, AccessShareLock);

	heap_fetch_toast_slice(toastrel, toast_pointer.va_valueid,
							   toast_pointer.va_extinfo, offset, length,
							   result);

	table_close(toastrel, AccessShareLock);

	return PointerGetDatum(result);
}

Datum genericToast(Relation toast_rel,
								Datum newvalue, Datum oldvalue,
								int max_inline_size)
{
	struct varlena *new_attr = (struct varlena *) DatumGetPointer(newvalue);
	struct varlena *old_attr = (struct varlena *) DatumGetPointer(oldvalue);
/*    varatt_external new_toast_pointer;
    varatt_external old_toast_pointer;
*/
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

void *
genericGetVtable(Datum toast_ptr)
{
    GenericToastRoutine *routine = palloc0(sizeof(*routine));

	routine->magic = GENERIC_TOASTER_MAGIC;

	return routine;
}

Datum
genericDeleteToast(Relation rel, Datum toast_ptr)
{
	PG_RETURN_VOID();
}

bool
genericToasterValidate(Oid toasteroid)
{
	bool result = true;

	return result;
}

PG_FUNCTION_INFO_V1(generic_toaster_handler);
Datum generic_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);
	tsrroutine->toast = genericToast;
	tsrroutine->detoast = genericDetoast;
	tsrroutine->deltoast = genericDeleteToast;
	tsrroutine->get_vtable = genericGetVtable;
	tsrroutine->toastervalidate = genericToasterValidate;
	PG_RETURN_POINTER(tsrroutine);
}

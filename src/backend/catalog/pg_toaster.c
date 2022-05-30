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

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/toasterapi.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "storage/lmgr.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/pg_lsn.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "access/toasterapi.h"
#include "access/detoast.h"
/*
extern bool toastrel_valueid_exists(Relation toastrel, Oid valueid);
extern bool toastid_valueid_exists(Oid toastrelid, Oid valueid);

extern Datum
toast_save_datum(Relation rel, Datum value,
	 struct varlena *oldexternal, int options);

extern void
heap_fetch_toast_slice(Relation toastrel, Oid valueid, int32 attrsize,
		   int32 sliceoffset, int32 slicelength,
		   struct varlena *result);
*/
/*
 *  * Validate the generic options given to a FOREIGN DATA WRAPPER, SERVER,
 *   * USER MAPPING or FOREIGN TABLE that uses file_fdw.
 *    *
 *     * Raise an ERROR if the option or its value is considered invalid.
 *      */
/*
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
	TsrRoutine *routine = palloc0(sizeof(*routine));
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

	PG_RETURN_POINTER(tsr);
}
*/

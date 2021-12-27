#include "postgres.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/toasterapi.h"
#include "access/toast_internals.h"
#include "catalog/pg_am.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_type.h"
#include "utils/fmgrprotos.h"
#include "access/detoast.h"
#include "fmgr.h"
#include "access/htup_details.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/xact.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
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
#include "access/detoast.h"
#include "access/genam.h"
#include "access/toast_helper.h"
#include "access/toast_internals.h"
#include "utils/fmgroids.h"
#include "access/generic_toaster.h"


#define VARATT_CUSTOM_TOASTER_GET_DATA(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	memcpy(&(toast_pointer), VARATT_CUSTOM_GET_DATA(attre), VARHDRSZ_EXTERNAL); \
	((varatt_custom)(toast_pointer)).va_toasterdata = VARATT_CUSTOM_GET_DATA(attre) + VARHDRSZ_EXTERNAL; \
} while (0)

/*
 * Callback function signatures --- see indexam.sgml for more info.
 */

/* Toast function */
static struct varlena*
genericToast(Relation toast_rel, Datum value, Datum oldvalue,
			 int options)
{
	Datum result;

	Assert(toast_rel != NULL);

	result = toast_save_datum(toast_rel, value,
							  (struct varlena *) DatumGetPointer(oldvalue),
							  options);
	return (struct varlena*)DatumGetPointer(result);
}

/* Detoast function */
static struct varlena*
genericDetoast(Relation toast_rel, Datum toast_ptr, int offset, int length)
{
	struct varlena *result = 0;
	struct varatt_external *toast_pointer = (struct varatt_external*)DatumGetPointer(toast_ptr);
	if( offset == 0
		&& length >= VARATT_EXTERNAL_GET_EXTSIZE(*toast_pointer) )
	{
		result = toast_fetch_datum(toast_pointer);
	}
	else
	{
		result = toast_fetch_datum_slice((struct varlena *)(toast_pointer),
										 offset, length);
	}

	return result;
}

/* Delete toast function */
static Datum
genericDeleteToast(Relation toast_rel, Datum value)
{
	struct varlena *result = 0;
	toast_delete_datum(toast_rel, value, false);
	return PointerGetDatum(result);
}

/* Return virtual table of functions */
static Size
genericGetRawsize(Datum toast_ptr)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	Size		result;

	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		/* va_rawsize is the size of the original datum -- including header */
		struct varatt_external toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);
		result = toast_pointer.va_rawsize;
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		struct varatt_indirect toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(toast_pointer.pointer));

		return genericGetRawsize(PointerGetDatum(toast_pointer.pointer));
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		result = EOH_get_flat_size(DatumGetEOHP(toast_ptr));
	}
	else if (VARATT_IS_COMPRESSED(attr))
	{
		/* here, va_rawsize is just the payload size */
		result = VARDATA_COMPRESSED_GET_EXTSIZE(attr) + VARHDRSZ;
	}
	else if (VARATT_IS_SHORT(attr))
	{
		/*
		 * we have to normalize the header length to VARHDRSZ or else the
		 * callers of this function will be confused.
		 */
		result = VARSIZE_SHORT(attr) - VARHDRSZ_SHORT + VARHDRSZ;
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		/*
		 * Custom toaster pointer size
		 */
		result = VARATT_CUSTOM_GET_DATA_SIZE(attr) + VARHDRSZ_EXTERNAL;
	}
	else
	{
		/* plain untoasted datum */
		result = VARSIZE(attr);
	}
	return result;
}

/* Return virtual table of functions */
static Size
genericGetSize(Datum toast_ptr)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	Size		result;

	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		/*
		 * Attribute is stored externally - return the extsize whether
		 * compressed or not.  We do not count the size of the toast pointer
		 * ... should we?
		 */
		struct varatt_external toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);
		result = VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer);
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		struct varatt_indirect toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(attr));

		return genericGetSize(PointerGetDatum(toast_pointer.pointer));
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		result = EOH_get_flat_size(DatumGetEOHP(toast_ptr));
	}
	else if (VARATT_IS_SHORT(attr))
	{
		result = VARSIZE_SHORT(attr);
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		result = VARATT_CUSTOM_GET_DATA_SIZE(attr);
	}
	else
	{
		/*
		 * Attribute is stored inline either compressed or not, just calculate
		 * the size of the datum in either case.
		 */
		result = VARSIZE(attr);
	}
	return result;
}

/* validate definition of a toaster Oid */
static bool
genericValidate(Oid typeoid, char storage, char compression,
				 Oid amoid, bool false_ok)
{
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
	tsrroutine->toastervalidate = genericValidate;

	PG_RETURN_POINTER(tsrroutine);
}

#include "postgres.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/toasterapi.h"
#include "access/toast_internals.h"
#include "catalog/pg_am.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_type.h"
#include "utils/fmgrprotos.h"
#include "access/toasterapi.h"
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
#include "access/heapam.h"
#include "access/genam.h"
#include "access/toast_helper.h"
#include "utils/fmgroids.h"
#include "access/generic_toaster.h"


#define VARATT_CUSTOM_TOASTER_GET_DATA(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	memcpy(&(toast_pointer), VARATT_CUSTOM_GET_DATA(attre), VARHDRSZ_EXTERNAL); \
	((varatt_custom)(toast_pointer)).va_toasterdata = VARATT_CUSTOM_GET_DATA(attre) + VARHDRSZ_EXTERNAL; \
} while (0)

/*
 * Callback function signatures --- see toaster.sgml for more info.
 */

static void
genericToastInit(Relation rel, Datum reloptions, LOCKMODE lockmode,
				 bool check, Oid OIDOldToast)
{
	(void) create_toast_table(rel, InvalidOid, InvalidOid, reloptions, lockmode,
							  check, OIDOldToast);
}


/* Toast function */
static struct varlena*
genericToast(Relation toast_rel, Oid toasterid, Datum value, Datum oldvalue,
			 int max_inline_size, int options)
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
genericDetoast(Datum toast_ptr, int offset, int length)
{
	struct varlena *result = 0;
	struct varlena *tvalue = (struct varlena*)DatumGetPointer(toast_ptr);
	struct varatt_external toast_pointer;

	VARATT_EXTERNAL_GET_POINTER(toast_pointer, tvalue);
	if(offset == 0
	   && (length < 0 || length >= VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer)))
	{
		result = toast_fetch_datum(tvalue);
	}
	else
	{
		result = toast_fetch_datum_slice(tvalue,
										 offset, length);
	}

	return result;
}

/* Delete toast function */
static void
genericDeleteToast(Datum value, bool is_speculative)
{
	toast_delete_datum(value, is_speculative);
}

/* validate definition of a toaster Oid */
static bool
genericValidate (Oid typeoid, char storage, char compression,
				 Oid amoid, bool false_ok)
{
	return true;
}

Datum
default_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);

	tsrroutine->init = genericToastInit;
	tsrroutine->toast = genericToast;
	tsrroutine->detoast = genericDetoast;
	tsrroutine->deltoast = genericDeleteToast;
	tsrroutine->get_vtable = NULL;
	tsrroutine->toastervalidate = genericValidate;

	PG_RETURN_POINTER(tsrroutine);
}

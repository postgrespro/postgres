/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Dummy toaster for tests
 *
 * Portions Copyright (c) 2023, Postgres Professional
 *
 * IDENTIFICATION
 *	  contrib/toastapi/dummy_toaster.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "toastapi.h"
#include "toastapi_internals.h"
#include "access/toast_helper.h"
#include "utils/builtins.h"

static Datum
dummy_toaster_init(Relation rel, Datum reloptions,
				   LOCKMODE lockmode, bool check, Oid OIDOldToast,
				   ToastAttributes tattrs)
{
	Datum toastrelid = (Datum) 0;

	if(tattrs->create_table_ind)
		toastrelid = ToastCreateToastTable(rel, tattrs->toasteroid, reloptions, tattrs->attnum, lockmode, OIDOldToast);
	else
		toastrelid = rel->rd_rel->reltoastrelid;

	tattrs->toastreloid = DatumGetObjectId(toastrelid);

	return toastrelid;
}

static bool
dummy_toaster_validate(Oid toasteroid, Oid typeoid,
					   char storage, char compression,
					   Oid amoid, bool false_ok)
{
	if (typeoid != BYTEAOID)
	{
		if (false_ok)
			return false;

		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("toaster \"%s\" does not support type %s",
						get_toaster_name(toasteroid),
						format_type_be(typeoid))));
	}

	if (storage != TYPSTORAGE_EXTENDED)
	{
		if (false_ok)
			return false;

		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("toaster \"%s\" supports only %s",
						get_toaster_name(toasteroid), "STORAGE EXTENDED")));
	}

	if (compression != TOAST_PGLZ_COMPRESSION_ID)
	{
		if (false_ok)
			return false;

		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("toaster \"%s\" supports only pglz compression",
						get_toaster_name(toasteroid))));
	}

	return true;
}

static void
dummy_toaster_delete_toast(Relation rel, Datum oldval, bool is_speculative,
							ToastAttributes tattrs)
{
}

static Datum
dummy_toaster_copy_toast(Relation rel, Datum newval,
						 int options,
						 ToastAttributes tattrs)
{
	return (Datum) 0;
}

static Datum
dummy_toaster_toast(Relation rel,
					Datum newval, Datum oldval,
					int max_inline_size, int options,
					ToastAttributes tattrs)
{
	return (Datum) 0;
}

static Datum
dummy_toaster_update_toast(Relation rel,
						   Datum newval, Datum oldval, int options,
						   ToastAttributes tattrs)
{
	return (Datum) 0;
}

static Datum
dummy_toaster_detoast(Datum toastptr,
					  int sliceoffset, int slicelength,
					  ToastAttributes tattrs)
{
	return (Datum) 0;
}

PG_FUNCTION_INFO_V1(dummy_toaster_handler);

Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsr = makeNode(TsrRoutine);

	tsr->init = dummy_toaster_init;
	tsr->toast = dummy_toaster_toast;
	tsr->deltoast = dummy_toaster_delete_toast;
	tsr->copy_toast = dummy_toaster_copy_toast;
	tsr->update_toast = dummy_toaster_update_toast;
	tsr->detoast = dummy_toaster_detoast;
	tsr->toastervalidate = dummy_toaster_validate;
	tsr->get_vtable = NULL;

	PG_RETURN_POINTER(tsr);
}

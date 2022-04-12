/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Dummy toaster for Toaster API.
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
#include "nodes/makefuncs.h"

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(dummy_toaster_handler);

#define MAX_DUMMY_CHUNK_SIZE 1024

/*
 * Dummy Toaster is a sample custom toaster for developers to show Toaster API
 * functionality and correct way to add new Toasters to PgSQL.
 */


/*
 * Dummy detoast function, does nothing
 */
static Datum
dummy_detoast(Relation toast_rel, Datum toast_ptr,
			 int offset, int length)
{
	struct varlena *result;
	result = palloc(0);
	return PointerGetDatum(result);
}

/*
 * Dummy Toast function, does nothing
 */
static Datum
dummy_toast(Relation toast_rel, Oid toasterid,
		   Datum value, Datum oldvalue,
		   int max_inline_size,  int options)
{
	struct varlena			*result;
	result = palloc(0);
	return PointerGetDatum(result);
}

/*
 * Dummy deltoast function, does nothing
 */
static void
dummy_delete(Datum value, bool is_speculative)
{
}

/*
 * Dummy init function, does nothing
 */
static void
dummy_toast_init(Relation rel, Datum reloptions, LOCKMODE lockmode,
				 bool check, Oid OIDOldToast)
{
}

/*
 * Dummy validation function, always returns TRUE
 */
static bool
dummy_toaster_validate(Oid typeoid,  char storage, char compression,
					 Oid amoid, bool false_ok)
{
	return true;
}

/*
 * Dummy toaster handler.
 * All Toaster functions declared in toasterapi.h and implemented in Custom
 * Toasters must be assigned to TsrRoutine structure
 */
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
	tsr->toastervalidate = NULL;

	PG_RETURN_POINTER(tsr);
}

/*----------------------------------------------------------------------
 *
 * generic_toaster.c
 *		Default (generic) toaster used by Toast tables by default
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 * 	src/backend/access/toast/generic_toaster.c
 *
 * NOTES
 *	  Generic toaster is used by Toast mechanics by default. Existing
 *	  Toast functions are routed via new API
 *	  generic_toaster.c is higher-level implementation, where lower-level
 *	  functions are implemented in toast_internals.c
 *
 *----------------------------------------------------------------------
 */

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
#include "replication/reorderbuffer.h"

/*
 * Callback function signatures --- see toaster.sgml for more info.
 */

/*
 * Init function. Creates Toast table for Toasted data storage
 * Default Toast mechanics uses heap storage mechanics
 */
static void
generic_toast_init(Relation rel, Oid toasterid,
				   Oid toastoid, Oid toastindexoid,
				   Datum reloptions, LOCKMODE lockmode,
				   bool check, Oid OIDOldToast)
{
	(void) create_toast_table(rel, toasterid, toastoid, toastindexoid,
							  reloptions, lockmode, check, OIDOldToast);
}


/*
 * Generic Toast function. Uses table created in Init function for data storage
 */
static Datum
generic_toast(Relation toast_rel, Oid toasterid, Datum value, Datum oldvalue,
			 int max_inline_size, int options)
{
	Datum result;

	Assert(toast_rel != NULL);

	result = toast_save_datum(toast_rel, toasterid, value,
							  (struct varlena *) DatumGetPointer(oldvalue),
							  options);
	return result;
}

/*
 * Generic Detoast function. Retrieves stored Toasted data, can be used to retrieve
 * toast slices
 */
static Datum
generic_detoast(Datum toast_ptr, int offset, int length)
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

	return PointerGetDatum(result);
}

/*
 * Generic Delete toast data function. Searches for given Toast datum and deletes it
 * (marks as dead)
 */
static void
generic_delete_toast(Datum value, bool is_speculative)
{
	toast_delete_datum(value, is_speculative);
}

/*
 * Generic Validate function. Always returns true
 */
static bool
generic_validate (Oid typeoid, char storage, char compression,
				 Oid amoid, bool false_ok)
{
	return true;
}

struct varlena *
generic_toaster_reconstruct(Relation toastrel, struct varlena *varlena,
							HTAB *toast_hash)
{
	struct varatt_external toast_pointer;
	struct varlena *reconstructed;
	ReorderBufferToastEnt *ent;
	dlist_iter	it;
	Size		data_done = 0;
	TupleDesc	toast_desc;

	if (!VARATT_IS_EXTERNAL_ONDISK(varlena))
		return NULL;

	if (!toast_hash)
		return NULL;

	VARATT_EXTERNAL_GET_POINTER(toast_pointer, varlena);

	/*
	 * Check whether the toast tuple changed, replace if so.
	 */
	ent = (ReorderBufferToastEnt *)
		hash_search(toast_hash,
					(void *) &toast_pointer.va_valueid,
					HASH_FIND,
					NULL);

	if (ent == NULL)
		return NULL;

	reconstructed = palloc0(toast_pointer.va_rawsize);

	ent->reconstructed = reconstructed;

	toast_desc = RelationGetDescr(toastrel);

	/* stitch toast tuple back together from its parts */
	dlist_foreach(it, &ent->chunks)
	{
		bool		isnull;
		ReorderBufferChange *cchange;
		ReorderBufferTupleBuf *ctup;
		Pointer		chunk;

		cchange = dlist_container(ReorderBufferChange, node, it.cur);
		ctup = cchange->data.tp.newtuple;
		chunk = DatumGetPointer(fastgetattr(&ctup->tuple, 3, toast_desc, &isnull));

		Assert(!isnull);
		Assert(!VARATT_IS_EXTERNAL(chunk));
		Assert(!VARATT_IS_SHORT(chunk));

		memcpy(VARDATA(reconstructed) + data_done,
			   VARDATA(chunk),
			   VARSIZE(chunk) - VARHDRSZ);
		data_done += VARSIZE(chunk) - VARHDRSZ;
	}
	Assert(data_done == VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer));

	/* make sure its marked as compressed or not */
	if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
		SET_VARSIZE_COMPRESSED(reconstructed, data_done + VARHDRSZ);
	else
		SET_VARSIZE(reconstructed, data_done + VARHDRSZ);

	return reconstructed;
}

static struct varlena *
generic_reconstruct(Relation toastrel, struct varlena *varlena,
					HTAB *toast_hash, bool *need_free)
{
	*need_free = false;
	return generic_toaster_reconstruct(toastrel, varlena, toast_hash);
}

Datum
default_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);

	tsrroutine->init = generic_toast_init;
	tsrroutine->toast = generic_toast;
	tsrroutine->detoast = generic_detoast;
	tsrroutine->deltoast = generic_delete_toast;
	tsrroutine->update_toast = NULL;
	tsrroutine->copy_toast = NULL;
	tsrroutine->get_vtable = NULL;
	tsrroutine->toastervalidate = generic_validate;
	tsrroutine->reconstruct = generic_reconstruct;

	PG_RETURN_POINTER(tsrroutine);
}

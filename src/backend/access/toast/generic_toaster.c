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
#include "access/toast_compression.h"
#include "replication/reorderbuffer.h"

/*
 * Callback function signatures --- see toaster.sgml for more info.
 */

/*
 * Init function. Creates Toast table for Toasted data storage
 * Default Toast mechanics uses heap storage mechanics
 */
static void
generic_toast_init(Relation rel, Oid toastoid, Oid toastindexoid, Datum reloptions, LOCKMODE lockmode,
		   bool check, Oid OIDOldToast)
{
	(void) create_toast_table(rel, toastoid, toastindexoid, reloptions, lockmode,
				  check, OIDOldToast);
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

	result = toast_save_datum(toast_rel, value,
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

/* Detoast iterator functions */
void
free_detoast_iterator_resources(DetoastIterator iter)
{
	if (iter->compressed && iter->buf)
	{
		free_toast_buffer(iter->buf);
		iter->buf = NULL;
	}

	if (iter->fetch_datum_iterator)
		free_fetch_datum_iterator(iter->fetch_datum_iterator);
	iter->fetch_datum_iterator = NULL;

	if (iter->self_ptr)
		*iter->self_ptr = NULL;
}

/* ----------
 * create_detoast_iterator -
 *
 * It only makes sense to initialize a de-TOAST iterator for external on-disk values.
 *
 * ----------
 */
DetoastIterator
create_detoast_iterator(struct varlena *attr)
{
	struct varatt_external toast_pointer;
	DetoastIterator iter;
	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		FetchDatumIterator fetch_iter;

		iter = (DetoastIterator) palloc0(sizeof(DetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;
		iter->gen.free_callback.func = (void (*)(void *)) free_detoast_iterator_resources;

		/* This is an externally stored datum --- initialize fetch datum iterator */
		iter->fetch_datum_iterator = fetch_iter = create_fetch_datum_iterator(attr);
		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);
		if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
		{
			iter->compressed = true;
			iter->compression_method = VARATT_EXTERNAL_GET_COMPRESS_METHOD(toast_pointer);

			/* prepare buffer to received decompressed data */
			iter->buf = create_toast_buffer(toast_pointer.va_rawsize, false);
		}
		else
		{
			iter->compressed = false;
			iter->compression_method = TOAST_INVALID_COMPRESSION_ID;

			/* point the buffer directly at the raw data */
			iter->buf = fetch_iter->buf;
		}
		return iter;
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		/* indirect pointer --- dereference it */
		struct varatt_indirect redirect;

		VARATT_EXTERNAL_GET_POINTER(redirect, attr);
		attr = (struct varlena *) redirect.pointer;

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(attr));

		/* recurse in case value is still extended in some other way */
		return create_detoast_iterator(attr);

	}
	else if (1 && VARATT_IS_COMPRESSED(attr))
	{
		ToastBuffer *buf;

		iter = (DetoastIterator) palloc0(sizeof(DetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;
		iter->gen.free_callback.func = (void (*)(void *)) free_detoast_iterator_resources;

		iter->fetch_datum_iterator = palloc0(sizeof(*iter->fetch_datum_iterator));
		iter->fetch_datum_iterator->buf = buf = create_toast_buffer(VARSIZE_ANY(attr), true);
		iter->fetch_datum_iterator->done = true;
		iter->compressed = true;
		iter->compression_method = VARDATA_COMPRESSED_GET_COMPRESS_METHOD(attr);

		memcpy((void *) buf->buf, attr, VARSIZE_ANY(attr));
		buf->limit = (char *) buf->capacity;

		/* prepare buffer to received decompressed data */
		iter->buf = create_toast_buffer(TOAST_COMPRESS_EXTSIZE(attr) + VARHDRSZ, false);

		return iter;
	}
	else
		/* in-line value -- no iteration used, even if it's compressed */
		return NULL;
}

/* ----------
 * free_detoast_iterator -
 *
 * Free memory used by the de-TOAST iterator, including buffers and
 * fetch datum iterator.
 * ----------
 */
void
free_detoast_iterator(DetoastIterator iter)
{
	if (iter == NULL)
		return;

	if (--iter->nrefs > 0)
		return;

	free_detoast_iterator_resources(iter);

	if (!iter->gen.free_callback.arg)
		pfree(iter);
}

static void
create_fetch_datum_iterator_scan(FetchDatumIterator iter)
{
	int			validIndex;

	MemoryContext oldcxt = MemoryContextSwitchTo(iter->mcxt);

	/*
	 * Open the toast relation and its indexes
	 */
	iter->toastrel = table_open(iter->toast_pointer.va_toastrelid, AccessShareLock);

	/* Look for the valid index of the toast relation */
	validIndex = toast_open_indexes(iter->toastrel,
									AccessShareLock,
									&iter->toastidxs,
									&iter->num_indexes);

	/*
	 * Setup a scan key to fetch from the index by va_valueid
	 */
	ScanKeyInit(&iter->toastkey,
				(AttrNumber) 1,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(iter->toast_pointer.va_valueid));

	/*
	 * Read the chunks by index
	 *
	 * Note that because the index is actually on (valueid, chunkidx) we will
	 * see the chunks in chunkidx order, even though we didn't explicitly ask
	 * for it.
	 */

	init_toast_snapshot(&iter->snapshot);
	iter->toastscan = systable_beginscan_ordered(iter->toastrel, iter->toastidxs[validIndex],
												 &iter->snapshot, 1, &iter->toastkey);

	MemoryContextSwitchTo(oldcxt);
}

/* ----------
 * create_fetch_datum_iterator -
 *
 * Initialize fetch datum iterator.
 * ----------
 */
FetchDatumIterator
create_fetch_datum_iterator(struct varlena *attr)
{
	FetchDatumIterator iter;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr))
		elog(ERROR, "create_fetch_datum_iterator shouldn't be called for non-ondisk datums");

	iter = (FetchDatumIterator) palloc0(sizeof(FetchDatumIteratorData));

	iter->mcxt = CurrentMemoryContext;

	/* Must copy to access aligned fields */
	VARATT_EXTERNAL_GET_POINTER(iter->toast_pointer, attr);

	iter->ressize = VARATT_EXTERNAL_GET_EXTSIZE(iter->toast_pointer);
	iter->numchunks = ((iter->ressize - 1) / TOAST_MAX_CHUNK_SIZE) + 1;

	iter->buf = create_toast_buffer(iter->ressize + VARHDRSZ,
									VARATT_EXTERNAL_IS_COMPRESSED(iter->toast_pointer));

	iter->nextidx = 0;
	iter->done = false;

	return iter;
}

void
free_fetch_datum_iterator(FetchDatumIterator iter)
{
	if (iter == NULL)
		return;

	if (!iter->done && iter->toastscan)
	{
		systable_endscan_ordered(iter->toastscan);
		toast_close_indexes(iter->toastidxs, iter->num_indexes, AccessShareLock);
		table_close(iter->toastrel, AccessShareLock);
	}
	free_toast_buffer(iter->buf);
	pfree(iter);
}

/* ----------
 * fetch_datum_iterate -
 *
 * Iterate through the toasted value referenced by iterator.
 *
 * As long as there is another chunk data in external storage,
 * fetch it into iterator's toast buffer.
 * ----------
 */
void
fetch_datum_iterate(FetchDatumIterator iter)
{
	HeapTuple	ttup;
	TupleDesc	toasttupDesc;
	int32		residx;
	Pointer		chunk;
	bool		isnull;
	char		*chunkdata;
	int32		chunksize;

	Assert(iter != NULL && !iter->done);

	if (!iter->toastscan)
		create_fetch_datum_iterator_scan(iter);

	ttup = systable_getnext_ordered(iter->toastscan, ForwardScanDirection);
	if (ttup == NULL)
	{
		/*
		 * Final checks that we successfully fetched the datum
		 */
		if (iter->nextidx != iter->numchunks)
			elog(ERROR, "missing chunk number %d for toast value %u in %s",
				 iter->nextidx,
				 iter->toast_pointer.va_valueid,
				 RelationGetRelationName(iter->toastrel));

		/*
		 * End scan and close relations
		 */
		systable_endscan_ordered(iter->toastscan);
		toast_close_indexes(iter->toastidxs, iter->num_indexes, AccessShareLock);
		table_close(iter->toastrel, AccessShareLock);

		iter->done = true;
		return;
	}

	/*
	 * Have a chunk, extract the sequence number and the data
	 */
	toasttupDesc = iter->toastrel->rd_att;
	residx = DatumGetInt32(fastgetattr(ttup, 2, toasttupDesc, &isnull));
	Assert(!isnull);
	chunk = DatumGetPointer(fastgetattr(ttup, 3, toasttupDesc, &isnull));
	Assert(!isnull);
	if (!VARATT_IS_EXTENDED(chunk))
	{
		chunksize = VARSIZE(chunk) - VARHDRSZ;
		chunkdata = VARDATA(chunk);
	}
	else if (VARATT_IS_SHORT(chunk))
	{
		/* could happen due to heap_form_tuple doing its thing */
		chunksize = VARSIZE_SHORT(chunk) - VARHDRSZ_SHORT;
		chunkdata = VARDATA_SHORT(chunk);
	}
	else
	{
		/* should never happen */
		elog(ERROR, "found toasted toast chunk for toast value %u in %s",
			 iter->toast_pointer.va_valueid,
			 RelationGetRelationName(iter->toastrel));
		chunksize = 0;		/* keep compiler quiet */
		chunkdata = NULL;
	}

	/*
	 * Some checks on the data we've found
	 */
	if (residx != iter->nextidx)
		elog(ERROR, "unexpected chunk number %d (expected %d) for toast value %u in %s",
			 residx, iter->nextidx,
			 iter->toast_pointer.va_valueid,
			 RelationGetRelationName(iter->toastrel));
	if (residx < iter->numchunks - 1)
	{
		if (chunksize != TOAST_MAX_CHUNK_SIZE)
			elog(ERROR, "unexpected chunk size %d (expected %d) in chunk %d of %d for toast value %u in %s",
				 chunksize, (int) TOAST_MAX_CHUNK_SIZE,
				 residx, iter->numchunks,
				 iter->toast_pointer.va_valueid,
				 RelationGetRelationName(iter->toastrel));
	}
	else if (residx == iter->numchunks - 1)
	{
		if ((residx * TOAST_MAX_CHUNK_SIZE + chunksize) != iter->ressize)
			elog(ERROR, "unexpected chunk size %d (expected %d) in final chunk %d for toast value %u in %s",
				 chunksize,
				 (int) (iter->ressize - residx * TOAST_MAX_CHUNK_SIZE),
				 residx,
				 iter->toast_pointer.va_valueid,
				 RelationGetRelationName(iter->toastrel));
	}
	else
		elog(ERROR, "unexpected chunk number %d (out of range %d..%d) for toast value %u in %s",
			 residx,
			 0, iter->numchunks - 1,
			 iter->toast_pointer.va_valueid,
			 RelationGetRelationName(iter->toastrel));

	/*
	 * Copy the data into proper place in our iterator buffer
	 */
	memcpy(iter->buf->limit, chunkdata, chunksize);
	iter->buf->limit += chunksize;

	iter->nextidx++;
}

/* ----------
 * create_toast_buffer -
 *
 * Create and initialize a TOAST buffer.
 *
 * size: buffer size include header
 * compressed: whether TOAST value is compressed
 * ----------
 */
ToastBuffer *
create_toast_buffer(int32 size, bool compressed)
{
	ToastBuffer *buf = (ToastBuffer *) palloc0(sizeof(ToastBuffer));
	buf->buf = (const char *) palloc(size);
	if (compressed)
	{
		SET_VARSIZE_COMPRESSED(buf->buf, size);
		/*
		 * Note the constraint buf->position <= buf->limit may be broken
		 * at initialization. Make sure that the constraint is satisfied
		 * when consuming chars.
		 */
		buf->position = VARDATA_4B_C(buf->buf);
	}
	else
	{
		SET_VARSIZE(buf->buf, size);
		buf->position = VARDATA_4B(buf->buf);
	}
	buf->limit = VARDATA(buf->buf);
	buf->capacity = buf->buf + size;

	return buf;
}

void
free_toast_buffer(ToastBuffer *buf)
{
	if (buf == NULL)
		return;

	pfree((void *)buf->buf);
	pfree(buf);
}

void
toast_decompress_iterate(ToastBuffer *source, ToastBuffer *dest,
						 ToastCompressionId compression_method,
						 void **decompression_state,
						 const char *destend)
{
	const char *sp;
	const char *srcend;
	char	   *dp;
	int32		dlen;
	int32		slen;
	bool		last_source_chunk;

	/*
	 * In the while loop, sp may be incremented such that it points beyond
	 * srcend. To guard against reading beyond the end of the current chunk,
	 * we set srcend such that we exit the loop when we are within four bytes
	 * of the end of the current chunk. When source->limit reaches
	 * source->capacity, we are decompressing the last chunk, so we can (and
	 * need to) read every byte.
	 */
	last_source_chunk = source->limit == source->capacity;
	srcend = last_source_chunk ? source->limit : source->limit - 4;
	sp = source->position;
	dp = dest->limit;
	if (destend > dest->capacity)
		destend = dest->capacity;

	slen = srcend - source->position;

	/*
	 * Decompress the data using the appropriate decompression routine.
	 */
	switch (compression_method)
	{
		case TOAST_PGLZ_COMPRESSION_ID:
			dlen = pglz_decompress_state(sp, &slen, dp, destend - dp,
										 last_source_chunk && destend == dest->capacity,
										 last_source_chunk,
										 decompression_state);
			break;
		case TOAST_LZ4_COMPRESSION_ID:
			if (source->limit < source->capacity)
				dlen = 0;	/* LZ4 needs need full data to decompress */
			else
			{
				/* decompress the data */
#ifndef USE_LZ4
				NO_LZ4_SUPPORT();
				dlen = 0;
#else
				dlen = LZ4_decompress_safe(source->buf + VARHDRSZ_COMPRESSED,
										   VARDATA(dest->buf),
										   VARSIZE(source->buf) - VARHDRSZ_COMPRESSED,
										   VARDATA_COMPRESSED_GET_EXTSIZE(source->buf));

				if (dlen < 0)
					ereport(ERROR,
							(errcode(ERRCODE_DATA_CORRUPTED),
							 errmsg_internal("compressed lz4 data is corrupt")));
#endif
				slen = 0;
			}
			break;
		default:
			elog(ERROR, "invalid compression method id %d", compression_method);
			return;		/* keep compiler quiet */
	}

	if (dlen < 0)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("compressed data is corrupt")));

	source->position += slen;
	dest->limit += dlen;
}

Datum generic_iterator_create(Datum value)
{
	DetoastIterator iter = create_detoast_iterator((struct varlena *) DatumGetPointer(value));
	return PointerGetDatum(iter);
}

void generic_iterate_next(Datum detoast_iter, Datum buf)
{
	DetoastIterator iter = (DetoastIterator) DatumGetPointer(detoast_iter);
	char *tmp = (char*) DatumGetPointer(buf);
	detoast_iterate(iter, tmp);
}

static void *
generic_toaster_vtable(Datum toast_ptr)
{
	GenericToastRoutine *routine = palloc0(sizeof(*routine));

	routine->magic = GENERIC_TOASTER_MAGIC;
	routine->detoast_iterator_create = generic_iterator_create;
	routine->detoast_iterate_next = generic_iterate_next;

	return routine;
}

struct varlena *
generic_toaster_reconstruct(Relation toastrel, struct varlena *varlena,
                                HTAB *toast_hash)
{
       struct varatt_external toast_pointer;
       struct varlena *reconstructed;
       ReorderBufferToastEnt *ent;
       dlist_iter      it;
       Size            data_done = 0;
       TupleDesc       toast_desc;

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
               bool            isnull;
               ReorderBufferChange *cchange;
               ReorderBufferTupleBuf *ctup;
               Pointer         chunk;

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

static Datum
generic_reconstruct(Relation toastrel, struct varlena *varlena,
                                       HTAB *toast_hash, bool *need_free)
{
       *need_free = false;
       return PointerGetDatum(generic_toaster_reconstruct(toastrel, varlena, toast_hash));
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
	tsrroutine->get_vtable = generic_toaster_vtable;
	tsrroutine->reconstruct = generic_reconstruct;
	tsrroutine->toastervalidate = generic_validate;

	PG_RETURN_POINTER(tsrroutine);
}

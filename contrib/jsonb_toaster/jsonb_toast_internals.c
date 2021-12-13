/*-------------------------------------------------------------------------
 *
 * jsonb_toast_internals.c
 *	 Implementaion of low-level jsonb TOAST.
 *
 * Copyright (c) 2022, PostgresPro
 *
 * IDENTIFICATION
 *	  contrib/jsonb_toaster/jsonb_toast_internals.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/detoast.h"
#include "access/genam.h"
#include "access/gin_private.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/toast_internals.h"
#include "access/toasterapi.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/toasting.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "jsonb_toaster.h"
#include "miscadmin.h"
#include "utils/expandeddatum.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/jsonb.h"

static struct varlena *
jsonx_toast_create_pointer_with_tids(struct varatt_external *toast_pointer,
									 int data_size, Oid toasterid)
{
	uint32		nchunks =
		(data_size + TOAST_MAX_CHUNK_SIZE - 1) / TOAST_MAX_CHUNK_SIZE;
	int			inline_size = nchunks * sizeof(ItemPointerData) + sizeof(uint32);
	struct varlena *ptr = (struct varlena *) palloc(VARATT_CUSTOM_SIZE(TOAST_POINTER_SIZE + inline_size));
	char	   *data;

	SET_VARTAG_EXTERNAL(ptr, VARTAG_CUSTOM);

	VARATT_CUSTOM_SET_TOASTERID(ptr, toasterid);
	VARATT_CUSTOM_SET_DATA_RAW_SIZE(ptr, data_size + VARHDRSZ);
	VARATT_CUSTOM_SET_DATA_SIZE(ptr, TOAST_POINTER_SIZE + inline_size);

	data = VARATT_CUSTOM_GET_DATA(ptr);
	Assert((intptr_t) data == INTALIGN((intptr_t) data));

	SET_VARTAG_EXTERNAL(data, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(data), toast_pointer, sizeof(*toast_pointer));
	memset(data + TOAST_POINTER_SIZE, 0, inline_size);
	memcpy(data + TOAST_POINTER_SIZE, &nchunks, sizeof(uint32));

	return ptr;
}

typedef struct ToastTidList
{
	uint16		nitems;
	GinPostingList list;
} ToastTidList;

struct varlena *
jsonx_toast_compress_tids(struct varlena *chunk_tids, int max_size)
{
	ItemPointer items;
	Pointer		ptr;
	uint32		nitems;
	int			nrootitems = 0;
	int			rootsize = 0;
	uint32		ntids;
	int			inlineSize = VARATT_CUSTOM_GET_DATA_SIZE(chunk_tids);
	struct varlena *compressed_tids;

	Assert(VARATT_IS_CUSTOM(chunk_tids));

	items = (ItemPointer)((char *) VARATT_CUSTOM_GET_DATA(chunk_tids) + TOAST_POINTER_SIZE + sizeof(uint32));
	inlineSize -= TOAST_POINTER_SIZE;
	nitems = (inlineSize - sizeof(uint32)) / sizeof(ItemPointerData);

	if (max_size <= TOAST_POINTER_SIZE + sizeof(uint32))
		return NULL;

	compressed_tids = palloc(max_size);

	SET_VARTAG_EXTERNAL(compressed_tids, VARTAG_CUSTOM);

	max_size -= VARATT_CUSTOM_SIZE(TOAST_POINTER_SIZE);

	ptr = (Pointer) VARATT_CUSTOM_GET_DATA(compressed_tids) + TOAST_POINTER_SIZE;
	ntids = nitems | 0x80000000;
	memcpy(ptr, &ntids, sizeof(uint32));
	ptr += sizeof(uint32);
	rootsize += sizeof(uint32);

	while (nrootitems < nitems)
	{
		ToastTidList jlist;
		GinPostingList *segment;
		int			npacked;
		int			segsize;

		segment = ginCompressPostingList(&items[nrootitems],
										 nitems - nrootitems,
#define JsonbTidsSegmentMaxSize 256
										 Min(max_size - rootsize - offsetof(ToastTidList, list), JsonbTidsSegmentMaxSize),
										 &npacked);
		segsize = SizeOfGinPostingList(segment);
		if (npacked <= 0 || rootsize + segsize > max_size)
		{
			pfree(compressed_tids);
			return NULL;
		}

		jlist.nitems = (uint16) npacked;
		memcpy(ptr, &jlist, offsetof(ToastTidList, list));
		ptr += offsetof(ToastTidList, list);
		rootsize += offsetof(ToastTidList, list);

		memcpy(ptr, segment, segsize);
		ptr += segsize;
		rootsize += segsize;

		nrootitems += npacked;
		pfree(segment);
	}

	VARATT_CUSTOM_SET_TOASTERID(compressed_tids, VARATT_CUSTOM_GET_TOASTERID(chunk_tids));
	VARATT_CUSTOM_SET_DATA_RAW_SIZE(compressed_tids, VARATT_CUSTOM_GET_DATA_RAW_SIZE(chunk_tids));
	VARATT_CUSTOM_SET_DATA_SIZE(compressed_tids, TOAST_POINTER_SIZE + rootsize);

	memcpy(VARATT_CUSTOM_GET_DATA(compressed_tids),
		   VARATT_CUSTOM_GET_DATA(chunk_tids),
		   TOAST_POINTER_SIZE);

	return compressed_tids;
}

static void
jsonx_toast_decompress_tid(void *compressed_tids, ItemPointer tids, int chunkno)
{
	ToastTidList *list = compressed_tids;
	int			base_chunkno = 0;

	if (ItemPointerIsValid(&tids[chunkno]))
		return;

	while (chunkno >= base_chunkno + list->nitems)
	{
		base_chunkno += list->nitems;
		list = (ToastTidList *)((char *) list + offsetof(ToastTidList, list) + SizeOfGinPostingList(&list->list));
	}

	ginPostingListDecodeOneSegment(&list->list, &tids[base_chunkno]);
}

static void
jsonx_toast_extract_chunk_fields(Relation toastrel, TupleDesc toasttupDesc,
						   Oid valueid, HeapTuple ttup, int32 *seqno,
						   char **chunkdata, int *chunksize);

static void
jsonx_toast_write_slice(Relation toastrel, Relation *toastidxs,
				  int num_indexes, int validIndex,
				  Oid valueid, int32 value_size, int32 slice_offset,
				  int32 slice_length, char *slice_data, int options,
				  ItemPointerData *chunk_tids)
{
	CommandId	mycid = GetCurrentCommandId(true);
	TupleDesc	toasttupDesc = toastrel->rd_att;
	union
	{
		struct varlena hdr;
		/* this is to make the union big enough for a chunk: */
		char		data[TOAST_MAX_CHUNK_SIZE + VARHDRSZ];
		/* ensure union is aligned well enough: */
		int32		align_it;
	}			chunk_data;
	int32		max_chunks_size = TOAST_MAX_CHUNK_SIZE;
	int32		chunk_size;
	int32		chunk_seq = slice_offset / max_chunks_size;
	int32		chunk_offset = chunk_seq * max_chunks_size;
	Datum		t_values[3];
	bool		t_isnull[3];

	Assert(chunk_offset == 0);

	/*
	 * Initialize constant parts of the tuple data
	 */
	t_values[0] = ObjectIdGetDatum(valueid);
	t_values[2] = PointerGetDatum(&chunk_data);
	t_isnull[0] = false;
	t_isnull[1] = false;
	t_isnull[2] = false;

	/*
	 * Split up the item into chunks
	 */
	while (slice_length > 0)
	{
		HeapTuple	toasttup;
		int32		old_chunk_size = chunk_offset >= value_size ? 0 :
			Min(max_chunks_size, value_size - chunk_offset);
		int32		chunk_slice_start = slice_offset <= chunk_offset ?
			0 : slice_offset - chunk_offset;
		int32		copied_slice_size =
			Min(max_chunks_size - chunk_slice_start, slice_length);

		CHECK_FOR_INTERRUPTS();

		/*
		 * Calculate the size of this chunk
		 */
		copied_slice_size = Min(max_chunks_size - chunk_slice_start, slice_length);
		chunk_size = Max(old_chunk_size, chunk_slice_start + copied_slice_size);

		/*
		 * Build a tuple and store it
		 */
		t_values[1] = Int32GetDatum(chunk_seq++);
		SET_VARSIZE(&chunk_data, chunk_size + VARHDRSZ);
		memcpy(VARDATA(&chunk_data) + chunk_slice_start, slice_data, copied_slice_size);
		toasttup = heap_form_tuple(toasttupDesc, t_values, t_isnull);

		heap_insert(toastrel, toasttup, mycid, options, NULL);

		if (chunk_tids)
			memcpy(&chunk_tids[chunk_seq - 1], &toasttup->t_self,
				   sizeof(ItemPointerData));

		if (!HeapTupleIsHeapOnly(toasttup))
		/*
		 * Create the index entry.  We cheat a little here by not using
		 * FormIndexDatum: this relies on the knowledge that the index columns
		 * are the same as the initial columns of the table for all the
		 * indexes.  We also cheat by not providing an IndexInfo: this is okay
		 * for now because btree doesn't need one, but we might have to be
		 * more honest someday.
		 *
		 * Note also that there had better not be any user-created index on
		 * the TOAST table, since we don't bother to update anything else.
		 */
		for (int i = 0; i < num_indexes; i++)
		{
			/* Only index relations marked as ready can be updated */
			if (toastidxs[i]->rd_index->indisready)
				index_insert(toastidxs[i], t_values, t_isnull,
							 &(toasttup->t_self),
							 toastrel,
							 toastidxs[i]->rd_index->indisunique ?
							 UNIQUE_CHECK_YES : UNIQUE_CHECK_NO,
							 false, NULL);
		}

		/*
		 * Free memory
		 */
		heap_freetuple(toasttup);

		/*
		 * Move on to next chunk
		 */
		chunk_offset += chunk_size;
		slice_length -= copied_slice_size;
		slice_data += copied_slice_size;
	}
}

/* ----------
 * toast_save_datum -
 *
 *	Save one single datum into the secondary relation and return
 *	a Datum reference for it.
 *
 * rel: the main relation we're working with (not the toast rel!)
 * value: datum to be pushed to toast storage
 * oldexternal: if not NULL, toast pointer previously representing the datum
 * options: options to be passed to heap_insert() for toast rows
 * ----------
 */
Datum
jsonx_toast_save_datum_ext(Relation rel, Oid toasterid, Datum value,
					 struct varlena *oldexternal, int options,
					 struct varlena **p_chunk_tids)
{
	Relation	toastrel;
	Relation   *toastidxs;
	struct varlena *result;
	struct varatt_external toast_pointer;
	char	   *data_p;
	int32		data_todo;
	Pointer		dval = DatumGetPointer(value);
	int			num_indexes;
	int			validIndex;
	ItemPointer	chunk_tids;

	Assert(!(VARATT_IS_EXTERNAL(value)));

	/*
	 * Open the toast relation and its indexes.  We can use the index to check
	 * uniqueness of the OID we assign to the toasted item, even though it has
	 * additional columns besides OID.
	 */
	toastrel = table_open(rel->rd_rel->reltoastrelid, RowExclusiveLock);

	/* Open all the toast indexes and look for the valid one */
	validIndex = toast_open_indexes(toastrel,
									RowExclusiveLock,
									&toastidxs,
									&num_indexes);

	/*
	 * Get the data pointer and length, and compute va_rawsize and va_extinfo.
	 *
	 * va_rawsize is the size of the equivalent fully uncompressed datum, so
	 * we have to adjust for short headers.
	 *
	 * va_extinfo stored the actual size of the data payload in the toast
	 * records and the compression method in first 2 bits if data is
	 * compressed.
	 */
	if (VARATT_IS_SHORT(dval))
	{
		data_p = VARDATA_SHORT(dval);
		data_todo = VARSIZE_SHORT(dval) - VARHDRSZ_SHORT;
		toast_pointer.va_rawsize = data_todo + VARHDRSZ;	/* as if not short */
		toast_pointer.va_extinfo = data_todo;
	}
	else if (VARATT_IS_COMPRESSED(dval))
	{
		data_p = VARDATA(dval);
		data_todo = VARSIZE(dval) - VARHDRSZ;
		/* rawsize in a compressed datum is just the size of the payload */
		toast_pointer.va_rawsize = VARDATA_COMPRESSED_GET_EXTSIZE(dval) + VARHDRSZ;

		/* set external size and compression method */
		VARATT_EXTERNAL_SET_SIZE_AND_COMPRESS_METHOD(toast_pointer, data_todo,
													 VARDATA_COMPRESSED_GET_COMPRESS_METHOD(dval));
		/* Assert that the numbers look like it's compressed */
		Assert(VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer));
	}
	else
	{
		data_p = VARDATA(dval);
		data_todo = VARSIZE(dval) - VARHDRSZ;
		toast_pointer.va_rawsize = VARSIZE(dval);
		toast_pointer.va_extinfo = data_todo;
	}

	/*
	 * Insert the correct table OID into the result TOAST pointer.
	 *
	 * Normally this is the actual OID of the target toast table, but during
	 * table-rewriting operations such as CLUSTER, we have to insert the OID
	 * of the table's real permanent toast table instead.  rd_toastoid is set
	 * if we have to substitute such an OID.
	 */
	if (OidIsValid(rel->rd_toastoid))
		toast_pointer.va_toastrelid = rel->rd_toastoid;
	else
		toast_pointer.va_toastrelid = RelationGetRelid(toastrel);

	/*
	 * Choose an OID to use as the value ID for this toast value.
	 *
	 * Normally we just choose an unused OID within the toast table.  But
	 * during table-rewriting operations where we are preserving an existing
	 * toast table OID, we want to preserve toast value OIDs too.  So, if
	 * rd_toastoid is set and we had a prior external value from that same
	 * toast table, re-use its value ID.  If we didn't have a prior external
	 * value (which is a corner case, but possible if the table's attstorage
	 * options have been changed), we have to pick a value ID that doesn't
	 * conflict with either new or existing toast value OIDs.
	 */
	if (!OidIsValid(rel->rd_toastoid))
	{
		/* normal case: just choose an unused OID */
		toast_pointer.va_valueid =
			GetNewOidWithIndex(toastrel,
							   RelationGetRelid(toastidxs[validIndex]),
							   (AttrNumber) 1);
	}
	else
	{
		/* rewrite case: check to see if value was in old toast table */
		toast_pointer.va_valueid = InvalidOid;
		if (oldexternal != NULL)
		{
			struct varatt_external old_toast_pointer;

			Assert(VARATT_IS_EXTERNAL_ONDISK(oldexternal));
			/* Must copy to access aligned fields */
			VARATT_EXTERNAL_GET_POINTER(old_toast_pointer, oldexternal);
			if (old_toast_pointer.va_toastrelid == rel->rd_toastoid)
			{
				/* This value came from the old toast table; reuse its OID */
				toast_pointer.va_valueid = old_toast_pointer.va_valueid;

				/*
				 * There is a corner case here: the table rewrite might have
				 * to copy both live and recently-dead versions of a row, and
				 * those versions could easily reference the same toast value.
				 * When we copy the second or later version of such a row,
				 * reusing the OID will mean we select an OID that's already
				 * in the new toast table.  Check for that, and if so, just
				 * fall through without writing the data again.
				 *
				 * While annoying and ugly-looking, this is a good thing
				 * because it ensures that we wind up with only one copy of
				 * the toast value when there is only one copy in the old
				 * toast table.  Before we detected this case, we'd have made
				 * multiple copies, wasting space; and what's worse, the
				 * copies belonging to already-deleted heap tuples would not
				 * be reclaimed by VACUUM.
				 */
				if (toastrel_valueid_exists(toastrel,
											toast_pointer.va_valueid))
				{
					/* Match, so short-circuit the data storage loop below */
					data_todo = 0;
				}
			}
		}
		if (toast_pointer.va_valueid == InvalidOid)
		{
			/*
			 * new value; must choose an OID that doesn't conflict in either
			 * old or new toast table
			 */
			do
			{
				toast_pointer.va_valueid =
					GetNewOidWithIndex(toastrel,
									   RelationGetRelid(toastidxs[validIndex]),
									   (AttrNumber) 1);
			} while (toastid_valueid_exists(rel->rd_toastoid,
											toast_pointer.va_valueid));
		}
	}

	if (p_chunk_tids)
	{
		*p_chunk_tids = jsonx_toast_create_pointer_with_tids(&toast_pointer, data_todo, toasterid);
		chunk_tids = (ItemPointer)(VARATT_CUSTOM_GET_DATA(*p_chunk_tids) + TOAST_POINTER_SIZE + sizeof(uint32));
	}
	else
		chunk_tids = NULL;

	jsonx_toast_write_slice(toastrel, toastidxs, num_indexes, validIndex,
					  toast_pointer.va_valueid, 0, 0, data_todo, data_p,
					  options, chunk_tids);

	/*
	 * Done - close toast relation and its indexes but keep the lock until
	 * commit, so as a concurrent reindex done directly on the toast relation
	 * would be able to wait for this transaction.
	 */
	toast_close_indexes(toastidxs, num_indexes, NoLock);
	table_close(toastrel, NoLock);

	/*
	 * Create the TOAST pointer value that we'll return
	 */
	result = (struct varlena *) palloc(TOAST_POINTER_SIZE);
	SET_VARTAG_EXTERNAL(result, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(result), &toast_pointer, sizeof(toast_pointer));

	return PointerGetDatum(result);
}

Datum
jsonx_toast_save_datum(Relation rel, Datum value,
				 struct varlena *oldexternal, int options)
{
	return jsonx_toast_save_datum_ext(rel, InvalidOid, value, oldexternal, options, NULL);
}

/* ----------
 * toast_delete_datum -
 *
 *	Delete a single external stored value.
 * ----------
 */
void
jsonx_toast_delete_datum(Datum value, bool is_speculative)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	struct varatt_external toast_pointer;
	Relation	toastrel;
	Relation   *toastidxs;
	ScanKeyData toastkey;
	SysScanDesc toastscan;
	HeapTuple	toasttup;
	int			num_indexes;
	int			validIndex;
	SnapshotData SnapshotToast;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr))
		return;

	/* Must copy to access aligned fields */
	VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

	/*
	 * Open the toast relation and its indexes
	 */
	toastrel = table_open(toast_pointer.va_toastrelid, RowExclusiveLock);

	/* Fetch valid relation used for process */
	validIndex = toast_open_indexes(toastrel,
									RowExclusiveLock,
									&toastidxs,
									&num_indexes);

	/*
	 * Setup a scan key to find chunks with matching va_valueid
	 */
	ScanKeyInit(&toastkey,
				(AttrNumber) 1,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(toast_pointer.va_valueid));

	/*
	 * Find all the chunks.  (We don't actually care whether we see them in
	 * sequence or not, but since we've already locked the index we might as
	 * well use systable_beginscan_ordered.)
	 */
	init_toast_snapshot(&SnapshotToast);
	toastscan = systable_beginscan_ordered(toastrel, toastidxs[validIndex],
										   &SnapshotToast, 1, &toastkey);
	while ((toasttup = systable_getnext_ordered(toastscan, ForwardScanDirection)) != NULL)
	{
		/*
		 * Have a chunk, delete it
		 */
		if (is_speculative)
			heap_abort_speculative(toastrel, &toasttup->t_self);
		else
			simple_heap_delete(toastrel, &toasttup->t_self);
	}

	/*
	 * End scan and close relations but keep the lock until commit, so as a
	 * concurrent reindex done directly on the toast relation would be able to
	 * wait for this transaction.
	 */
	systable_endscan_ordered(toastscan);
	toast_close_indexes(toastidxs, num_indexes, NoLock);
	table_close(toastrel, NoLock);
}

static void
jsonx_process_toast_chunk(Relation toastrel, Oid valueid, struct varlena *result,
					int chunk_data_size, int attrsize, int chunksize,
					char *chunkdata, int curchunk, int expectedchunk,
					int startchunk, int endchunk, int totalchunks,
					int32 sliceoffset, int32 slicelength)
{
	int32		expected_size;
	int32		chcpystrt;
	int32		chcpyend;

	/*
	 * Some checks on the data we've found
	 */
	if (curchunk != expectedchunk)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("unexpected chunk number %d (expected %d) for toast value %u in %s",
								 curchunk, expectedchunk, valueid,
								 RelationGetRelationName(toastrel))));
	if (curchunk > endchunk)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("unexpected chunk number %d (out of range %d..%d) for toast value %u in %s",
								 curchunk,
								 startchunk, endchunk, valueid,
								 RelationGetRelationName(toastrel))));
	expected_size = curchunk < totalchunks - 1 ? chunk_data_size
		: attrsize - ((totalchunks - 1) * chunk_data_size);
	Assert(chunksize == expected_size);
	if (chunksize != expected_size)
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("unexpected chunk size %d (expected %d) in chunk %d of %d for toast value %u in %s",
								 chunksize, expected_size,
								 curchunk, totalchunks, valueid,
								 RelationGetRelationName(toastrel))));

	/*
	 * Copy the data into proper place in our result
	 */
	chcpystrt = 0;
	chcpyend = chunksize - 1;
	if (curchunk == startchunk)
		chcpystrt = sliceoffset % chunk_data_size;
	if (curchunk == endchunk)
		chcpyend = (sliceoffset + slicelength - 1) % chunk_data_size;

	memcpy(VARDATA(result) +
		   (curchunk * chunk_data_size - sliceoffset) + chcpystrt,
		   chunkdata + chcpystrt,
		   (chcpyend - chcpystrt) + 1);
}

static void
jsonx_toast_extract_chunk_fields(Relation toastrel, TupleDesc toasttupDesc,
						   Oid valueid, HeapTuple ttup, int32 *seqno,
						   char **chunkdata, int *chunksize)
{
	Pointer		chunk;
	bool		isnull;

	/*
	 * Have a chunk, extract the sequence number and the data
	 */
	*seqno = DatumGetInt32(fastgetattr(ttup, 2, toasttupDesc, &isnull));
	Assert(!isnull);

	chunk = DatumGetPointer(fastgetattr(ttup, 3, toasttupDesc, &isnull));
	Assert(!isnull);

	if (!VARATT_IS_EXTENDED(chunk))
	{
		*chunksize = VARSIZE(chunk) - VARHDRSZ;
		*chunkdata = VARDATA(chunk);
	}
	else if (VARATT_IS_SHORT(chunk))
	{
		/* could happen due to heap_form_tuple doing its thing */
		*chunksize = VARSIZE_SHORT(chunk) - VARHDRSZ_SHORT;
		*chunkdata = VARDATA_SHORT(chunk);
	}
	else
	{
		/* should never happen */
		elog(ERROR, "found toasted toast chunk for toast value %u in %s",
			 valueid, RelationGetRelationName(toastrel));
		*chunksize = 0;		/* keep compiler quiet */
		*chunkdata = NULL;
	}
}

static void
jsonx_create_fetch_datum_iterator_scan(JsonxFetchDatumIterator iter, int32 first_chunkno)
{
	MemoryContext oldcxt = MemoryContextSwitchTo(iter->mcxt);

	if (!iter->toastrel)
	{
		/*
		 * Open the toast relation and its indexes
		 */
		iter->toastrel = table_open(iter->toast_pointer.va_toastrelid, AccessShareLock);

		/* Look for the valid index of the toast relation */
		iter->valid_index = toast_open_indexes(iter->toastrel,
											   AccessShareLock,
											   &iter->toastidxs,
											   &iter->num_indexes);

		init_toast_snapshot(&iter->snapshot);
	}

	/*
	 * Setup a scan key to fetch from the index by va_valueid
	 */
	ScanKeyInit(&iter->toastkey[0],
				(AttrNumber) 1,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(iter->toast_pointer.va_valueid));

	if (first_chunkno > 0)
		ScanKeyInit(&iter->toastkey[1],
					(AttrNumber) 2,
					BTGreaterEqualStrategyNumber, F_INT4GE,
					Int32GetDatum(first_chunkno));

	/*
	 * Read the chunks by index
	 *
	 * Note that because the index is actually on (valueid, chunkidx) we will
	 * see the chunks in chunkidx order, even though we didn't explicitly ask
	 * for it.
	 */

	iter->toastscan = systable_beginscan_ordered(iter->toastrel,
												 iter->toastidxs[iter->valid_index],
												 &iter->snapshot,
												 first_chunkno > 0 ? 2 : 1,
												 iter->toastkey);
	iter->nextidx = first_chunkno;

	MemoryContextSwitchTo(oldcxt);
}

/* ----------
 * create_fetch_datum_iterator -
 *
 * Initialize fetch datum iterator.
 * ----------
 */
static JsonxFetchDatumIterator
jsonx_create_fetch_datum_iterator(struct varlena *attr)
{
	JsonxFetchDatumIterator iter;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr))
		elog(ERROR, "create_fetch_datum_iterator shouldn't be called for non-ondisk datums");

	iter = (JsonxFetchDatumIterator) palloc0(sizeof(JsonxFetchDatumIteratorData));

	iter->mcxt = CurrentMemoryContext;

	/* Must copy to access aligned fields */
	VARATT_EXTERNAL_GET_POINTER(iter->toast_pointer, attr);

	iter->chunksize = TOAST_MAX_CHUNK_SIZE;
	iter->ressize = VARATT_EXTERNAL_GET_EXTSIZE(iter->toast_pointer);
	iter->numchunks = ((iter->ressize - 1) / iter->chunksize) + 1;

	iter->buf = create_toast_buffer(iter->ressize + VARHDRSZ,
									VARATT_EXTERNAL_IS_COMPRESSED(iter->toast_pointer));

	iter->nextidx = 0;
	iter->done = false;
	iter->chunks_bitmap = palloc0((iter->numchunks + 7) / 8);

	return iter;
}

static void
jsonx_free_fetch_datum_iterator(JsonxFetchDatumIterator iter)
{
	if (iter == NULL)
		return;

	if (!iter->done)
	{
		if (iter->toastscan)
			systable_endscan_ordered(iter->toastscan);

		if (!iter->cached)
		{
			if (iter->toastrel)
			{
				if (iter->num_indexes > 0)
					toast_close_indexes(iter->toastidxs, iter->num_indexes, AccessShareLock);
				table_close(iter->toastrel, AccessShareLock);
			}

			if (iter->slot)
				ExecDropSingleTupleTableSlot(iter->slot);

			if (iter->heapfetch)
				table_index_fetch_end(iter->heapfetch);
		}

		if (iter->compressed_chunk_tids)
			pfree(iter->chunk_tids);
	}
	free_toast_buffer(iter->buf);
	pfree(iter);
}

typedef struct ToastTIdScanCache
{
	Relation toastrel;
	struct TupleTableSlot *slot;
	struct IndexFetchTableData *heapfetch;
	ResourceOwner resowner;
	MemoryContextCallback free_callback;
} ToastTIdScanCache;

static void
jsonx_free_toast_cache(void *arg)
{
	ToastTIdScanCache *cache = arg;
	ResourceOwner old_resowner = CurrentResourceOwner;

	CurrentResourceOwner = cache->resowner;

	if (cache->toastrel)
		table_close(cache->toastrel, AccessShareLock);

	if (cache->slot)
		ExecDropSingleTupleTableSlot(cache->slot);

	if (cache->heapfetch)
		table_index_fetch_end(cache->heapfetch);

	CurrentResourceOwner = old_resowner;
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
static void
jsonx_fetch_datum_iterate(JsonxFetchDatumIterator iter)
{
	HeapTuple	ttup;
	int32		residx;
	char		*chunkdata;
	int32		chunksize;

	Assert(iter != NULL && !iter->done);

	if (iter->chunk_tids)
	{
		bool		all_dead = false;
		bool		found;
		bool		heap_continue = false;
		bool		shouldFree = false;

		ToastTIdScanCache *cache = NULL;

		if (0 && jsonb_iter_cache)
		{
			cache = *jsonb_iter_cache;

			if (!cache)
			{
				*jsonb_iter_cache = cache = MemoryContextAllocZero(jsonb_iter_cache_mcxt, sizeof(*cache));

				cache->free_callback.func = jsonx_free_toast_cache;
				cache->free_callback.arg = cache;
				MemoryContextRegisterResetCallback(jsonb_iter_cache_mcxt, &cache->free_callback);
			}
		}

		if (!iter->toastrel)
		{
			MemoryContext oldcxt = MemoryContextSwitchTo(cache ? jsonb_iter_cache_mcxt : iter->mcxt);

			if (cache && cache->toastrel)
			{
				iter->toastrel = cache->toastrel;
				iter->slot = cache->slot;
				iter->heapfetch = cache->heapfetch;

				init_toast_snapshot(&iter->snapshot);
			}
			else
			{
				if (!iter->toastrel)
				{
					iter->toastrel = table_open(iter->toast_pointer.va_toastrelid, AccessShareLock);

#if 0
					/* Look for the valid index of the toast relation */
					iter->valid_index = toast_open_indexes(iter->toastrel,
														   AccessShareLock,
														   &iter->toastidxs,
														   &iter->num_indexes);
#endif
					init_toast_snapshot(&iter->snapshot);
				}

				iter->slot = table_slot_create(iter->toastrel, NULL);
				iter->heapfetch = table_index_fetch_begin(iter->toastrel);

				if (cache)
				{
					cache->toastrel = iter->toastrel;
					cache->slot = iter->slot;
					cache->heapfetch = iter->heapfetch;
					cache->resowner = CurrentResourceOwner;

					iter->cached = true;
				}
			}

			MemoryContextSwitchTo(oldcxt);
		}

		if (iter->nextidx >= iter->nchunk_tids)
			found = false;
		else
		{
			ItemPointerData tid;

			if (iter->compressed_chunk_tids)
				jsonx_toast_decompress_tid(iter->compressed_chunk_tids, iter->chunk_tids, iter->nextidx);

			tid = iter->chunk_tids[iter->nextidx];

			found = table_index_fetch_tuple(iter->heapfetch, &tid,
											&iter->snapshot, iter->slot,
											&heap_continue, &all_dead);

			//Assert(!heap_continue);
		}

		if (!found)
		{
			if (!iter->cached)
			{
				table_index_fetch_end(iter->heapfetch);
				if (iter->num_indexes > 0)
					toast_close_indexes(iter->toastidxs, iter->num_indexes, AccessShareLock);
				table_close(iter->toastrel, AccessShareLock);
				ExecDropSingleTupleTableSlot(iter->slot);
			}

			iter->done = true;
			return;
		}

		ttup = ExecFetchSlotHeapTuple(iter->slot, false, &shouldFree);
		Assert(!shouldFree);
	}
	else
	{

	if (!iter->toastscan)
		jsonx_create_fetch_datum_iterator_scan(iter, iter->nextidx);

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
	}

	/*
	 * Have a chunk, extract the sequence number and the data
	 */
	jsonx_toast_extract_chunk_fields(iter->toastrel, iter->toastrel->rd_att,
									 iter->toast_pointer.va_valueid, ttup,
									 &residx, &chunkdata, &chunksize);

	//jsonx_process_toast_chunk(iter->toastrel, iter->toast_pointer.va_valueid, ...);

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

	iter->chunks_bitmap[iter->nextidx / 8] |= 1 << (iter->nextidx % 8);

	iter->nextidx++;
}


static void
jsonx_fetch_datum_iterate_to(JsonxFetchDatumIterator iter, int32 chunkno)
{
	if (iter->nextidx != chunkno)
	{
		if (iter->toastscan)
			systable_endscan_ordered(iter->toastscan);

		if (iter->chunk_tids)
			iter->nextidx = chunkno;
		else
			jsonx_create_fetch_datum_iterator_scan(iter, chunkno);

		iter->buf->limit = (char *) VARDATA(iter->buf->buf) + (Size) iter->chunksize * chunkno;
	}

	jsonx_fetch_datum_iterate(iter);
}

static void
jsonx_free_detoast_iterator_internal(JsonxDetoastIterator iter)
{
	if (iter->compressed && iter->buf)
	{
		free_toast_buffer(iter->buf);
		iter->buf = NULL;
	}

	if (iter->fetch_datum_iterator)
	{
		jsonx_free_fetch_datum_iterator(iter->fetch_datum_iterator);
		iter->fetch_datum_iterator = NULL;
	}

#ifdef JSONB_FREE_ITERATORS
	pfree(iter);
#endif
}

/* ----------
 * free_detoast_iterator -
 *
 * Free memory used by the de-TOAST iterator, including buffers and
 * fetch datum iterator.
 * ----------
 */

void
jsonx_free_detoast_iterator(JsonxDetoastIterator iter)
{
	if (iter == NULL)
		return;
	if (--iter->nrefs > 0)
		return;
	jsonx_free_detoast_iterator_internal(iter);
}

/* ----------
 * jsonx_create_detoast_iterator -
 *
 * It only makes sense to initialize a de-TOAST iterator for external on-disk values.
 *
 * ----------
 */
JsonxDetoastIterator
jsonx_create_detoast_iterator(struct varlena *attr)
{
	struct varatt_external toast_pointer;
	JsonxDetoastIterator iter;

	if (VARATT_IS_CUSTOM(attr))
	{
		JsonxFetchDatumIterator fetch_iter;
		char	   *data = (char *) INTALIGN((intptr_t) VARATT_CUSTOM_GET_DATA(attr));
		char	   *inlineData;
		uint32		inlineSize;
		uint32		ntids;

		if (!VARATT_IS_EXTERNAL_ONDISK(data))
			return NULL;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, data);

		iter = (JsonxDetoastIterator) palloc0(sizeof(JsonxDetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;
		iter->gen.free_callback.func = (void (*)(void *)) jsonx_free_detoast_iterator_internal;

		data = VARATT_CUSTOM_GET_DATA(attr);
		inlineData = data + TOAST_POINTER_SIZE;
		inlineSize = VARATT_CUSTOM_GET_DATA_SIZE(attr) - (data - (char *) VARATT_CUSTOM_GET_DATA(attr)) - TOAST_POINTER_SIZE;

		iter->fetch_datum_iterator = fetch_iter = jsonx_create_fetch_datum_iterator((struct varlena *) data);
		fetch_iter->toasterid = VARATT_CUSTOM_GET_TOASTERID(attr);

		memcpy(&ntids, inlineData, sizeof(uint32));

		fetch_iter->chunk_tids_inline_size = inlineSize;

		if (inlineSize <= 0)
		{
			fetch_iter->nchunk_tids = 0;
			fetch_iter->chunk_tids = NULL;
			fetch_iter->compressed_chunk_tids = NULL;
		}
		else if (ntids & 0x80000000)
		{
			fetch_iter->nchunk_tids = ntids & 0x7FFFFFFF;
			fetch_iter->chunk_tids = palloc0(sizeof(ItemPointerData) * fetch_iter->nchunk_tids);
			fetch_iter->compressed_chunk_tids = (char *) inlineData + sizeof(uint32);
		}
		else
		{
			fetch_iter->nchunk_tids = ntids;
			fetch_iter->chunk_tids = (ItemPointer)((char *) inlineData + sizeof(uint32));
			fetch_iter->compressed_chunk_tids = NULL;
			Assert(fetch_iter->nchunk_tids == (inlineSize - sizeof(uint32)) / sizeof(ItemPointerData));
		}

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
	else if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		JsonxFetchDatumIterator fetch_iter;

		iter = (JsonxDetoastIterator) palloc0(sizeof(JsonxDetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;
		iter->gen.free_callback.func = (void (*)(void *)) jsonx_free_detoast_iterator_internal;

		/* This is an externally stored datum --- initialize fetch datum iterator */
		iter->fetch_datum_iterator = fetch_iter = jsonx_create_fetch_datum_iterator(attr);
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
		return jsonx_create_detoast_iterator(attr);

	}
	else if (1 && VARATT_IS_COMPRESSED(attr))
	{
		ToastBuffer *buf;

		iter = (JsonxDetoastIterator) palloc0(sizeof(JsonxDetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;
		iter->gen.free_callback.func = (void (*)(void *)) jsonx_free_detoast_iterator_internal;

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

void
jsonx_detoast_iterate(JsonxDetoastIterator detoast_iter, const char *destend)
{
	JsonxFetchDatumIterator fetch_iter = detoast_iter->fetch_datum_iterator;

	Assert(detoast_iter != NULL && !detoast_iter->done);

	if (!detoast_iter->compressed)
		destend = NULL;

	if (1 && destend)
	{
		const char *srcend = (const char *)
			(fetch_iter->buf->limit == fetch_iter->buf->capacity ?
			fetch_iter->buf->limit : fetch_iter->buf->limit - 4);

		if (fetch_iter->buf->position >= srcend && !fetch_iter->done)
			jsonx_fetch_datum_iterate(fetch_iter);
	}
	else if (!fetch_iter->done)
		jsonx_fetch_datum_iterate(fetch_iter);

	if (detoast_iter->compressed)
		toast_decompress_iterate(fetch_iter->buf, detoast_iter->buf,
								 detoast_iter->compression_method,
								 &detoast_iter->decompression_state,
								 destend);

	if (detoast_iter->buf->limit == detoast_iter->buf->capacity)
	{
		detoast_iter->done = true;
#if 0	/* FIXME fetch_iter can be used after */
		if (detoast_iter->buf == fetch_iter->buf)
			fetch_iter->buf = NULL;
		jsonx_free_fetch_datum_iterator(fetch_iter);
		detoast_iter->fetch_datum_iterator = NULL;
#endif
	}
}

void
jsonx_detoast_iterate_slice(JsonxDetoastIterator detoast_iter, int32 offset, int32 length)
{
	JsonxFetchDatumIterator fetch_iter = detoast_iter->fetch_datum_iterator;
	int32		first_read_chunk_offset = -1;
	int32		maxoffset = offset - 4 + length;

	Assert(offset >= 0);
	Assert(length > 0);

	if (detoast_iter->compressed)
	{
		const char *need = detoast_iter->buf->buf + offset + length;

		Assert(need <= detoast_iter->buf->capacity);

		while (!detoast_iter->done && need > detoast_iter->buf->limit)
			jsonx_detoast_iterate(detoast_iter, need);

		return;
	}

#if 0
	if (fetch_iter->compressed_chunks)
	{
#define BITMAP_CHUNK_SIZE 128
		int32		maxoffset2 = (maxoffset + BITMAP_CHUNK_SIZE - 1) & ~(BITMAP_CHUNK_SIZE - 1);

		for (int32 byteno = (offset - 4) / BITMAP_CHUNK_SIZE; byteno < (maxoffset + BITMAP_CHUNK_SIZE - 1) / BITMAP_CHUNK_SIZE;)
		{
			uint8		mask = fetch_iter->chunks_bitmap[byteno / 8];

			if (mask == 0xFF)
				byteno = (byteno + 8) & ~7;
			else
			{
				if (!(mask & (1 << (byteno % 8))))
				{
					fetch_datum_iterate_to(fetch_iter, byteno * BITMAP_CHUNK_SIZE, maxoffset2);

					Assert(fetch_iter->chunks_bitmap[byteno / 8] & (1 << (byteno % 8)));

					if (first_read_chunk_offset < 0)
						first_read_chunk_offset = 4 + byteno * BITMAP_CHUNK_SIZE;
				}

				byteno++;
			}
		}
	}
	else
#endif
	{
		int32		maxchunk = (maxoffset + fetch_iter->chunksize - 1) / fetch_iter->chunksize;

		for (int32 chunkno = (offset - 4) / fetch_iter->chunksize;
			 chunkno < maxchunk;
			 chunkno++)
		{
			if (!(fetch_iter->chunks_bitmap[chunkno / 8] & (1 << (chunkno % 8))))
			{
				jsonx_fetch_datum_iterate_to(fetch_iter, chunkno /*, maxoffset */);
				if (first_read_chunk_offset < 0)
					first_read_chunk_offset = 4 + fetch_iter->chunksize * chunkno;
			}
		}
	}

	//Assert(need <= detoast_iter->buf->limit);
}

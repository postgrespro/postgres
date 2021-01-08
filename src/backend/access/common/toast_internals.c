/*-------------------------------------------------------------------------
 *
 * toast_internals.c
 *	  Functions for internal use by the TOAST system.
 *
 * Copyright (c) 2000-2021, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/common/toast_internals.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/detoast.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/toast_internals.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "common/pg_lzcompress.h"
#include "miscadmin.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"

static bool toastrel_valueid_exists(Relation toastrel, Oid valueid);
static bool toastid_valueid_exists(Oid toastrelid, Oid valueid);

/* ----------
 * toast_compress_datum -
 *
 *	Create a compressed version of a varlena datum
 *
 *	If we fail (ie, compressed result is actually bigger than original)
 *	then return NULL.  We must not use compressed data if it'd expand
 *	the tuple!
 *
 *	We use VAR{SIZE,DATA}_ANY so we can handle short varlenas here without
 *	copying them.  But we can't handle external or compressed datums.
 * ----------
 */
Datum
toast_compress_datum(Datum value, char cmethod)
{
	struct varlena *tmp = NULL;
	int32		valsize;
	ToastCompressionId	cmid = TOAST_INVALID_COMPRESSION_ID;

	Assert(!VARATT_IS_EXTERNAL(DatumGetPointer(value)));
	Assert(!VARATT_IS_COMPRESSED(DatumGetPointer(value)));

	Assert(CompressionMethodIsValid(cmethod));

	valsize = VARSIZE_ANY_EXHDR(DatumGetPointer(value));

	/*
	 * Call appropriate compression routine for the compression method.
	 */
	switch (cmethod)
	{
		case TOAST_PGLZ_COMPRESSION:
			tmp = pglz_compress_datum((const struct varlena *) value);
			cmid = TOAST_PGLZ_COMPRESSION_ID;
			break;
		case TOAST_LZ4_COMPRESSION:
			tmp = lz4_compress_datum((const struct varlena *) value);
			cmid = TOAST_LZ4_COMPRESSION_ID;
			break;
		default:
			elog(ERROR, "invalid compression method %c", cmethod);
	}

	if (tmp == NULL)
		return PointerGetDatum(NULL);

	/*
	 * We recheck the actual size even if compression reports success, because
	 * it might be satisfied with having saved as little as one byte in the
	 * compressed data --- which could turn into a net loss once you consider
	 * header and alignment padding.  Worst case, the compressed format might
	 * require three padding bytes (plus header, which is included in
	 * VARSIZE(tmp)), whereas the uncompressed format would take only one
	 * header byte and no padding if the value is short enough.  So we insist
	 * on a savings of more than 2 bytes to ensure we have a gain.
	 */
	if (VARSIZE(tmp) < valsize - 2)
	{
		/* successful compression */
		Assert(cmid != TOAST_INVALID_COMPRESSION_ID);
		TOAST_COMPRESS_SET_SIZE_AND_COMPRESS_METHOD(tmp, valsize, cmid);
		return PointerGetDatum(tmp);
	}
	else
	{
		/* incompressible data */
		pfree(tmp);
		return PointerGetDatum(NULL);
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
toast_save_datum(Relation rel, Datum value,
				 struct varlena *oldexternal, int options)
{
	Relation	toastrel;
	Relation   *toastidxs;
	HeapTuple	toasttup;
	TupleDesc	toasttupDesc;
	Datum		t_values[3];
	bool		t_isnull[3];
	CommandId	mycid = GetCurrentCommandId(true);
	struct varlena *result;
	struct varatt_external toast_pointer;
	union
	{
		struct varlena hdr;
		/* this is to make the union big enough for a chunk: */
		char		data[TOAST_MAX_CHUNK_SIZE + VARHDRSZ];
		/* ensure union is aligned well enough: */
		int32		align_it;
	}			chunk_data;
	int32		chunk_size;
	int32		chunk_seq = 0;
	char	   *data_p;
	int32		data_todo;
	Pointer		dval = DatumGetPointer(value);
	int			num_indexes;
	int			validIndex;

	Assert(!VARATT_IS_EXTERNAL(value));

	/*
	 * Open the toast relation and its indexes.  We can use the index to check
	 * uniqueness of the OID we assign to the toasted item, even though it has
	 * additional columns besides OID.
	 */
	toastrel = table_open(rel->rd_rel->reltoastrelid, RowExclusiveLock);
	toasttupDesc = toastrel->rd_att;

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

	/*
	 * Initialize constant parts of the tuple data
	 */
	t_values[0] = ObjectIdGetDatum(toast_pointer.va_valueid);
	t_values[2] = PointerGetDatum(&chunk_data);
	t_isnull[0] = false;
	t_isnull[1] = false;
	t_isnull[2] = false;

	/*
	 * Split up the item into chunks
	 */
	while (data_todo > 0)
	{
		int			i;

		CHECK_FOR_INTERRUPTS();

		/*
		 * Calculate the size of this chunk
		 */
		chunk_size = Min(TOAST_MAX_CHUNK_SIZE, data_todo);

		/*
		 * Build a tuple and store it
		 */
		t_values[1] = Int32GetDatum(chunk_seq++);
		SET_VARSIZE(&chunk_data, chunk_size + VARHDRSZ);
		memcpy(VARDATA(&chunk_data), data_p, chunk_size);
		toasttup = heap_form_tuple(toasttupDesc, t_values, t_isnull);

		heap_insert(toastrel, toasttup, mycid, options, NULL);

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
		for (i = 0; i < num_indexes; i++)
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
		data_todo -= chunk_size;
		data_p += chunk_size;
	}

	/*
	 * Done - close toast relation and its indexes
	 */
	toast_close_indexes(toastidxs, num_indexes, RowExclusiveLock);
	table_close(toastrel, RowExclusiveLock);

	/*
	 * Create the TOAST pointer value that we'll return
	 */
	result = (struct varlena *) palloc(TOAST_POINTER_SIZE);
	SET_VARTAG_EXTERNAL(result, VARTAG_ONDISK);
	memcpy(VARDATA_EXTERNAL(result), &toast_pointer, sizeof(toast_pointer));

	return PointerGetDatum(result);
}

/* ----------
 * toast_delete_datum -
 *
 *	Delete a single external stored value.
 * ----------
 */
void
toast_delete_datum(Relation rel, Datum value, bool is_speculative)
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
	 * End scan and close relations
	 */
	systable_endscan_ordered(toastscan);
	toast_close_indexes(toastidxs, num_indexes, RowExclusiveLock);
	table_close(toastrel, RowExclusiveLock);
}

/* ----------
 * toastrel_valueid_exists -
 *
 *	Test whether a toast value with the given ID exists in the toast relation.
 *	For safety, we consider a value to exist if there are either live or dead
 *	toast rows with that ID; see notes for GetNewOidWithIndex().
 * ----------
 */
static bool
toastrel_valueid_exists(Relation toastrel, Oid valueid)
{
	bool		result = false;
	ScanKeyData toastkey;
	SysScanDesc toastscan;
	int			num_indexes;
	int			validIndex;
	Relation   *toastidxs;

	/* Fetch a valid index relation */
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
				ObjectIdGetDatum(valueid));

	/*
	 * Is there any such chunk?
	 */
	toastscan = systable_beginscan(toastrel,
								   RelationGetRelid(toastidxs[validIndex]),
								   true, SnapshotAny, 1, &toastkey);

	if (systable_getnext(toastscan) != NULL)
		result = true;

	systable_endscan(toastscan);

	/* Clean up */
	toast_close_indexes(toastidxs, num_indexes, RowExclusiveLock);

	return result;
}

/* ----------
 * toastid_valueid_exists -
 *
 *	As above, but work from toast rel's OID not an open relation
 * ----------
 */
static bool
toastid_valueid_exists(Oid toastrelid, Oid valueid)
{
	bool		result;
	Relation	toastrel;

	toastrel = table_open(toastrelid, AccessShareLock);

	result = toastrel_valueid_exists(toastrel, valueid);

	table_close(toastrel, AccessShareLock);

	return result;
}

/* ----------
 * toast_get_valid_index
 *
 *	Get OID of valid index associated to given toast relation. A toast
 *	relation can have only one valid index at the same time.
 */
Oid
toast_get_valid_index(Oid toastoid, LOCKMODE lock)
{
	int			num_indexes;
	int			validIndex;
	Oid			validIndexOid;
	Relation   *toastidxs;
	Relation	toastrel;

	/* Open the toast relation */
	toastrel = table_open(toastoid, lock);

	/* Look for the valid index of the toast relation */
	validIndex = toast_open_indexes(toastrel,
									lock,
									&toastidxs,
									&num_indexes);
	validIndexOid = RelationGetRelid(toastidxs[validIndex]);

	/* Close the toast relation and all its indexes */
	toast_close_indexes(toastidxs, num_indexes, NoLock);
	table_close(toastrel, NoLock);

	return validIndexOid;
}

/* ----------
 * toast_open_indexes
 *
 *	Get an array of the indexes associated to the given toast relation
 *	and return as well the position of the valid index used by the toast
 *	relation in this array. It is the responsibility of the caller of this
 *	function to close the indexes as well as free them.
 */
int
toast_open_indexes(Relation toastrel,
				   LOCKMODE lock,
				   Relation **toastidxs,
				   int *num_indexes)
{
	int			i = 0;
	int			res = 0;
	bool		found = false;
	List	   *indexlist;
	ListCell   *lc;

	/* Get index list of the toast relation */
	indexlist = RelationGetIndexList(toastrel);
	Assert(indexlist != NIL);

	*num_indexes = list_length(indexlist);

	/* Open all the index relations */
	*toastidxs = (Relation *) palloc(*num_indexes * sizeof(Relation));
	foreach(lc, indexlist)
		(*toastidxs)[i++] = index_open(lfirst_oid(lc), lock);

	/* Fetch the first valid index in list */
	for (i = 0; i < *num_indexes; i++)
	{
		Relation	toastidx = (*toastidxs)[i];

		if (toastidx->rd_index->indisvalid)
		{
			res = i;
			found = true;
			break;
		}
	}

	/*
	 * Free index list, not necessary anymore as relations are opened and a
	 * valid index has been found.
	 */
	list_free(indexlist);

	/*
	 * The toast relation should have one valid index, so something is going
	 * wrong if there is nothing.
	 */
	if (!found)
		elog(ERROR, "no valid index found for toast relation with Oid %u",
			 RelationGetRelid(toastrel));

	return res;
}

/* ----------
 * toast_close_indexes
 *
 *	Close an array of indexes for a toast relation and free it. This should
 *	be called for a set of indexes opened previously with toast_open_indexes.
 */
void
toast_close_indexes(Relation *toastidxs, int num_indexes, LOCKMODE lock)
{
	int			i;

	/* Close relations and clean up things */
	for (i = 0; i < num_indexes; i++)
		index_close(toastidxs[i], lock);
	pfree(toastidxs);
}

/* ----------
 * init_toast_snapshot
 *
 *	Initialize an appropriate TOAST snapshot.  We must use an MVCC snapshot
 *	to initialize the TOAST snapshot; since we don't know which one to use,
 *	just use the oldest one.  This is safe: at worst, we will get a "snapshot
 *	too old" error that might have been avoided otherwise.
 */
void
init_toast_snapshot(Snapshot toast_snapshot)
{
	Snapshot	snapshot = GetOldestSnapshot();

	if (snapshot == NULL)
		elog(ERROR, "no known snapshots");

	InitToastSnapshot(*toast_snapshot, snapshot->lsn, snapshot->whenTaken);
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
	int			validIndex;
	FetchDatumIterator iter;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr))
		elog(ERROR, "create_fetch_datum_iterator shouldn't be called for non-ondisk datums");

	iter = (FetchDatumIterator) palloc0(sizeof(FetchDatumIteratorData));

	/* Must copy to access aligned fields */
	VARATT_EXTERNAL_GET_POINTER(iter->toast_pointer, attr);

	iter->ressize = iter->toast_pointer.va_extsize;
	iter->numchunks = ((iter->ressize - 1) / TOAST_MAX_CHUNK_SIZE) + 1;

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

	if (!iter->done)
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
	buf->buf = (const char *) palloc0(size);
	if (compressed) {
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

/* ----------
 * pglz_decompress_iterate -
 *
 * This function is based on pglz_decompress(), with these additional
 * requirements:
 *
 * 1. We need to save the current control byte and byte position for the
 * caller's next iteration.
 *
 * 2. In pglz_decompress(), we can assume we have all the source bytes
 * available. This is not the case when we decompress one chunk at a
 * time, so we have to make sure that we only read bytes available in the
 * current chunk.
 * ----------
 */
void
pglz_decompress_iterate(ToastBuffer *source, ToastBuffer *dest,
						DetoastIterator iter, unsigned char *destend)
{
	const unsigned char *sp;
	const unsigned char *srcend;
	unsigned char *dp;

	/*
	 * In the while loop, sp may be incremented such that it points beyond
	 * srcend. To guard against reading beyond the end of the current chunk,
	 * we set srcend such that we exit the loop when we are within four bytes
	 * of the end of the current chunk. When source->limit reaches
	 * source->capacity, we are decompressing the last chunk, so we can (and
	 * need to) read every byte.
	 */
	srcend = (const unsigned char *)
		(source->limit == source->capacity ? source->limit : (source->limit - 4));
	sp = (const unsigned char *) source->position;
	dp = (unsigned char *) dest->limit;
	if (destend > (unsigned char *) dest->capacity)
		destend = (unsigned char *) dest->capacity;

	if (iter->len)
	{
		int32		len = iter->len;
		int32		off = iter->off;
		int32		copylen = Min(len, destend - dp);
		int32		remlen = len - copylen;

		while (copylen--)
		{
			*dp = dp[-off];
			dp++;
		}

		iter->len = remlen;

		if (dp >= destend)
		{
			dest->limit = (char *) dp;
			return;
		}

		Assert(remlen == 0);
	}

	while (sp < srcend && dp < destend)
	{
		/*
		 * Read one control byte and process the next 8 items (or as many as
		 * remain in the compressed input).
		 */
		unsigned char ctrl;
		int			ctrlc;

		if (iter->ctrlc != INVALID_CTRLC)
		{
			ctrl = iter->ctrl;
			ctrlc = iter->ctrlc;
		}
		else
		{
			ctrl = *sp++;
			ctrlc = 0;
		}

		for (; ctrlc < INVALID_CTRLC && sp < srcend && dp < destend; ctrlc++)
		{

			if (ctrl & 1)
			{
				/*
				 * Set control bit means we must read a match tag. The match
				 * is coded with two bytes. First byte uses lower nibble to
				 * code length - 3. Higher nibble contains upper 4 bits of the
				 * offset. The next following byte contains the lower 8 bits
				 * of the offset. If the length is coded as 18, another
				 * extension tag byte tells how much longer the match really
				 * was (0-255).
				 */
				int32		len;
				int32		off;
				int32		copylen;

				len = (sp[0] & 0x0f) + 3;
				off = ((sp[0] & 0xf0) << 4) | sp[1];
				sp += 2;
				if (len == 18)
					len += *sp++;

				/*
				 * Now we copy the bytes specified by the tag from OUTPUT to
				 * OUTPUT (copy len bytes from dp - off to dp). The copied
				 * areas could overlap; to prevent possible uncertainty, we
				 * copy only non-overlapping regions.
				 */
				copylen = Min(len, destend - dp);
				iter->len = len - copylen;

				while (off < copylen)
				{
					/* see comments in common/pg_lzcompress.c */
					memcpy(dp, dp - off, off);
					copylen -= off;
					dp += off;
					off += off;
				}
				memcpy(dp, dp - off, copylen);
				dp += copylen;

				iter->off = off;
			}
			else
			{
				/*
				 * An unset control bit means LITERAL BYTE. So we just copy
				 * one from INPUT to OUTPUT.
				 */
				*dp++ = *sp++;
			}

			/*
			 * Advance the control bit
			 */
			ctrl >>= 1;
		}

		iter->ctrlc = ctrlc;
		iter->ctrl = ctrl;
	}

	source->position = (char *) sp;
	dest->limit = (char *) dp;
}

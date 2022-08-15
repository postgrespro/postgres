/*-------------------------------------------------------------------------
 *
 * toast_internals.c
 *	  Functions for internal use by the TOAST system.
 *
 * Copyright (c) 2000-2023, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/common/toast_internals.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/toasterapi.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/toast_internals.h"
#include "access/generic_toaster.h"
#include "catalog/toasting.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "common/pg_lzcompress.h"
#include "miscadmin.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"

static void
toast_extract_chunk_fields(Relation toastrel, TupleDesc toasttupDesc,
						   Oid valueid, HeapTuple ttup, int32 *seqno,
						   char **chunkdata, int *chunksize);

static void
toast_write_slice(Relation toastrel, Relation *toastidxs,
				  int num_indexes, int validIndex,
				  Oid valueid, int32 value_size, int32 slice_offset,
				  int32 slice_length, char *slice_data,
				  int options,
				  void *chunk_header, int chunk_header_size,
				  ToastChunkVisibilityCheck visibility_check,
				  void *visibility_cxt);

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
toast_save_datum_ext(Relation rel, Oid toasterid, Datum value,
					 struct varlena *oldexternal, int options,
					 void *chunk_header, int chunk_header_size)
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
	Oid			toastrelid;
	Oid			real_toastrelid;

	Assert(!(VARATT_IS_EXTERNAL(value)));

	toastrelid = toast_find_relation_for_toaster(rel, toasterid, &real_toastrelid);

	/*
	 * Open the toast relation and its indexes.  We can use the index to check
	 * uniqueness of the OID we assign to the toasted item, even though it has
	 * additional columns besides OID.
	 */
	toastrel = table_open(toastrelid, RowExclusiveLock);

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
	toast_pointer.va_toastrelid = real_toastrelid;

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
	if (toastrelid == real_toastrelid)
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

			/* New case - Generic TOAST working with Custom pointer */
			if(VARATT_IS_CUSTOM(oldexternal))
			{
				ExternalToastData data;
				VARATT_CUSTOM_GET_EXTERNAL_DATA(PointerGetDatum(oldexternal), data);
				old_toast_pointer.va_toastrelid = get_uint32align16(&data.va_toastrelid);
				old_toast_pointer.va_valueid = get_uint32align16(&data.va_valueid);
			}
			else
			{
				Assert(VARATT_IS_EXTERNAL_ONDISK(oldexternal));
				VARATT_EXTERNAL_GET_POINTER(old_toast_pointer, oldexternal);
			}
			/* Must copy to access aligned fields */
			/* VARATT_EXTERNAL_GET_POINTER(old_toast_pointer, oldexternal); */
			/* XXX if (old_toast_pointer.va_toastrelid == rel->rd_toastoid) */
			if (old_toast_pointer.va_toastrelid == real_toastrelid)
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
			} while (toastid_valueid_exists(real_toastrelid,
											toast_pointer.va_valueid));
		}
	}

	toast_write_slice(toastrel, toastidxs, num_indexes, validIndex,
					  toast_pointer.va_valueid, 0, 0, data_todo, data_p,
					  options, chunk_header, chunk_header_size,
					  NULL, NULL);

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
toast_save_datum(Relation rel, Oid toasterid, Datum value,
				 struct varlena *oldexternal, int options)
{
	return toast_save_datum_ext(rel, toasterid, value, oldexternal, options, NULL, 0);
}


/* ----------
 * toast_delete_datum -
 *
 *	Delete a single external stored value.
 * ----------
 */
void
toast_delete_datum(Datum value, bool is_speculative)
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
	ExternalToastData data;
	Oid va_toastrelid;
	Oid va_valueid;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr) && !VARATT_IS_CUSTOM(attr))
		return;

	/* Must copy to access aligned fields */
	if(VARATT_IS_CUSTOM(attr))
	{
		/* process custom Toast Pointer */
		VARATT_CUSTOM_GET_EXTERNAL_DATA(attr, data);

		va_toastrelid = get_uint32align16(&data.va_toastrelid);
		va_valueid = get_uint32align16(&data.va_valueid);
	}
	else
	{
		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		va_toastrelid = toast_pointer.va_toastrelid;
		va_valueid = toast_pointer.va_valueid;
	}

	/*
	 * Open the toast relation and its indexes
	 */
	toastrel = table_open(va_toastrelid, RowExclusiveLock);

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
				ObjectIdGetDatum(va_valueid));

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

/* ----------
 * toastrel_valueid_exists -
 *
 *	Test whether a toast value with the given ID exists in the toast relation.
 *	For safety, we consider a value to exist if there are either live or dead
 *	toast rows with that ID; see notes for GetNewOidWithIndex().
 * ----------
 */
bool
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
bool
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
 * toast_fetch_datum -
 *
 *	Reconstruct an in memory Datum from the chunks saved
 *	in the toast relation
 * ----------
 */
extern struct varlena *
toast_fetch_datum(struct varlena *attr)
{
	Relation	toastrel;
	struct varlena *result;
	struct varatt_external toast_pointer;
	ExternalToastData data;
	Oid va_toastrelid;
	Oid va_valueid;
	int32		attrsize;
	bool		is_compressed = false;

	if (!VARATT_IS_EXTERNAL_ONDISK(attr) && !VARATT_IS_CUSTOM(attr))
		elog(ERROR, "toast_fetch_datum_slice shouldn't be called for non-ondisk or non-custom datums");

	/* Must copy to access aligned fields */
	if(VARATT_IS_CUSTOM(attr))
	{
		/* process custom Toast Pointer */
		VARATT_CUSTOM_GET_EXTERNAL_DATA(attr, data);

		attrsize = get_uint32align16(&data.va_extinfo);
		va_toastrelid = get_uint32align16(&data.va_toastrelid);
		va_valueid = get_uint32align16(&data.va_valueid);

		if (VARATT_CUSTOM_EXTERNAL_IS_COMPRESSED(attr, attrsize))
			is_compressed = true;
	}
	else
	{
		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		va_toastrelid = toast_pointer.va_toastrelid;
		va_valueid = toast_pointer.va_valueid;

		attrsize = VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer);
		if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
			is_compressed = true;
	}

	result = (struct varlena *) palloc(attrsize + VARHDRSZ);

	if (is_compressed)
		SET_VARSIZE_COMPRESSED(result, attrsize + VARHDRSZ);
	else
		SET_VARSIZE(result, attrsize + VARHDRSZ);

	if (attrsize == 0)
		return result;			/* Probably shouldn't happen, but just in
								 * case. */

	/*
	 * Open the toast relation and its indexes
	 */
	toastrel = table_open(va_toastrelid, AccessShareLock);

	/* Fetch all chunks */
	toast_fetch_toast_slice(toastrel, va_valueid,
							attr, attrsize, 0, attrsize, result, 0,
							NULL, NULL);

	/* Close toast table */
	table_close(toastrel, AccessShareLock);

	return result;
}

/* ----------
 * toast_fetch_datum_slice -
 *
 *	Reconstruct a segment of a Datum from the chunks saved
 *	in the toast relation
 *
 *	Note that this function supports non-compressed external datums
 *	and compressed external datums (in which case the requested slice
 *	has to be a prefix, i.e. sliceoffset has to be 0).
 * ----------
 */
extern struct varlena *
toast_fetch_datum_slice(struct varlena *attr, int32 sliceoffset,
						int32 slicelength)
{
	Relation	toastrel;
	struct varlena *result;
	struct varatt_external toast_pointer;
	ExternalToastData data;
	Oid va_toastrelid;
	Oid va_valueid;
	int32		attrsize;
	bool		is_compressed = false;

	if (!(VARATT_IS_EXTERNAL_ONDISK(attr) || VARATT_IS_CUSTOM(attr)))
		elog(ERROR, "toast_fetch_datum_slice shouldn't be called for non-ondisk or non-custom datums");

	/* Must copy to access aligned fields */
	if(VARATT_IS_CUSTOM(attr))
	{
		/* process custom Toast Pointer */
		VARATT_CUSTOM_GET_EXTERNAL_DATA(attr, data);

		attrsize = get_uint32align16(&data.va_extinfo);
		va_toastrelid = get_uint32align16(&data.va_toastrelid);
		va_valueid = get_uint32align16(&data.va_valueid);

		if (VARATT_CUSTOM_EXTERNAL_IS_COMPRESSED(attr, attrsize) && slicelength > 0)
			is_compressed = true;
	}
	else
	{
		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		va_toastrelid = toast_pointer.va_toastrelid;
		va_valueid = toast_pointer.va_valueid;

		/*
		 * It's nonsense to fetch slices of a compressed datum unless when it's a
	 	 * prefix -- this isn't lo_* we can't return a compressed datum which is
	 	 * meaningful to toast later.
	 	 */
		Assert(!VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer) || 0 == sliceoffset);

		attrsize = VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer);
		if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer) && slicelength > 0)
			is_compressed = true;
	}


	if (sliceoffset >= attrsize)
	{
		sliceoffset = 0;
		slicelength = 0;
	}

	/*
	 * When fetching a prefix of a compressed external datum, account for the
	 * space required by va_tcinfo, which is stored at the beginning as an
	 * int32 value.
	 */
	/* if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer) && slicelength > 0) */
	if(is_compressed)
		slicelength = slicelength + sizeof(int32);

	/*
	 * Adjust length request if needed.  (Note: our sole caller,
	 * detoast_attr_slice, protects us against sliceoffset + slicelength
	 * overflowing.)
	 */
	if (((sliceoffset + slicelength) > attrsize) || slicelength < 0)
		slicelength = attrsize - sliceoffset;

	result = (struct varlena *) palloc(slicelength + VARHDRSZ);

	if(is_compressed)
		SET_VARSIZE_COMPRESSED(result, slicelength + VARHDRSZ);
	else
		SET_VARSIZE(result, slicelength + VARHDRSZ);

	if (slicelength == 0)
		return result;			/* Can save a lot of work at this point! */

	/* Open the toast relation */
	toastrel = table_open(va_toastrelid, AccessShareLock);

	/* Fetch all chunks */
	toast_fetch_toast_slice(toastrel, va_valueid,
							attr, attrsize, sliceoffset, slicelength,
							result, 0, NULL, NULL);

	/* Close toast table */
	table_close(toastrel, AccessShareLock);

	return result;
}

static void
process_toast_chunk(Relation toastrel, Oid valueid, struct varlena *result,
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

/*
 * Fetch a TOAST slice from a toast table.
 *
 * toastrel is the relation from which chunks are to be fetched.
 * valueid identifies the TOAST value from which chunks are being fetched.
 * attrsize is the total size of the TOAST value.
 * sliceoffset is the byte offset within the TOAST value from which to fetch.
 * slicelength is the number of bytes to be fetched from the TOAST value.
 * result is the varlena into which the results should be written.
 */
void
toast_fetch_toast_slice(Relation toastrel, Oid valueid,
						struct varlena *attr, int32 attrsize,
						int32 sliceoffset, int32 slicelength,
						struct varlena *result, int32 header_size,
						ToastChunkVisibilityCheck visibility_check,
						void *visibility_cxt)
{
	Relation   *toastidxs;
	ScanKeyData toastkey[3];
	TupleDesc	toasttupDesc = toastrel->rd_att;
	int			nscankeys;
	SysScanDesc toastscan;
	HeapTuple	ttup;
	int32		expectedchunk;
	int32		totalchunks;
	int			startchunk;
	int			endchunk;
	int			num_indexes;
	int			validIndex;
	SnapshotData SnapshotToast;
	Size		chunk_data_size = TOAST_MAX_CHUNK_SIZE - header_size;
	bool		versioned = header_size != 0;

	totalchunks = ((attrsize - 1) / chunk_data_size) + 1;

	/* Look for the valid index of toast relation */
	validIndex = toast_open_indexes(toastrel,
									AccessShareLock,
									&toastidxs,
									&num_indexes);

	startchunk = sliceoffset / chunk_data_size;
	endchunk = (sliceoffset + slicelength - 1) / chunk_data_size;
	Assert(endchunk <= totalchunks);

	/* Set up a scan key to fetch from the index. */
	ScanKeyInit(&toastkey[0],
				(AttrNumber) 1,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(valueid));

	/*
	 * No additional condition if fetching all chunks. Otherwise, use an
	 * equality condition for one chunk, and a range condition otherwise.
	 */
	if (startchunk == 0 && endchunk == totalchunks - 1)
		nscankeys = 1;
	else if (startchunk == endchunk)
	{
		ScanKeyInit(&toastkey[1],
					(AttrNumber) 2,
					BTEqualStrategyNumber, F_INT4EQ,
					Int32GetDatum(startchunk));
		nscankeys = 2;
	}
	else
	{
		ScanKeyInit(&toastkey[1],
					(AttrNumber) 2,
					BTGreaterEqualStrategyNumber, F_INT4GE,
					Int32GetDatum(startchunk));
		ScanKeyInit(&toastkey[2],
					(AttrNumber) 2,
					BTLessEqualStrategyNumber, F_INT4LE,
					Int32GetDatum(endchunk));
		nscankeys = 3;
	}

	/* Prepare for scan */
	init_toast_snapshot(&SnapshotToast);
	toastscan = systable_beginscan_ordered(toastrel, toastidxs[validIndex],
										   &SnapshotToast, nscankeys, toastkey);

	/*
	 * Catalog snapshots can be returned by GetOldestSnapshot() even if not
	 * registered or active. That easily hides bugs around not having a
	 * snapshot set up - most of the time there is a valid catalog snapshot.
	 * So additionally insist that the current snapshot is registered or
	 * active.
	 * Read the chunks by index
	 *
	 * The index is on (valueid, chunkidx) so they will come in order
	 */
	expectedchunk = startchunk;
	while ((ttup = systable_getnext_ordered(toastscan, ForwardScanDirection)) != NULL)
	{
		int32		curchunk;
		Pointer		chunk;
		bool		isnull;
		char	   *chunkdata;
		int32		chunksize;

		/*
		 * Have a chunk, extract the sequence number and the data
		 */
		curchunk = DatumGetInt32(fastgetattr(ttup, 2, toasttupDesc, &isnull));
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
				 valueid, RelationGetRelationName(toastrel));
			chunksize = 0;		/* keep compiler quiet */
			chunkdata = NULL;
		}

		if (versioned)
		{
			/* Skip aborted chunks */
			if (!HeapTupleHeaderXminCommitted(ttup->t_data))
			{
				TransactionId xmin = HeapTupleHeaderGetXmin(ttup->t_data);

				Assert(!HeapTupleHeaderXminInvalid(ttup->t_data));

				if (TransactionIdDidAbort(xmin))
					continue;
			}

			if (curchunk != expectedchunk)
			{
				char	   *chunkdata_ver = NULL;
				int32		chunksize_ver = 0;

				if (!visibility_check(visibility_cxt, &chunkdata_ver, &chunksize_ver, NULL))
					ereport(ERROR,
							(errcode(ERRCODE_DATA_CORRUPTED),
							 errmsg_internal("missing chunk number %d for toast value %u in %s",
											 expectedchunk, valueid,
											 RelationGetRelationName(toastrel))));

				chunkdata_ver += header_size;
				chunksize_ver -= header_size;

				process_toast_chunk(toastrel, valueid, result, chunk_data_size, attrsize,
									chunksize_ver, chunkdata_ver, expectedchunk,
									expectedchunk, startchunk, endchunk, totalchunks,
									sliceoffset, slicelength);
				expectedchunk++;
			}

			if (curchunk != expectedchunk)
				continue;

			if (!visibility_check(visibility_cxt, &chunkdata, &chunksize, NULL))
				continue;
		}

		process_toast_chunk(toastrel, valueid, result, chunk_data_size, attrsize,
							chunksize, chunkdata, curchunk,
							expectedchunk, startchunk, endchunk, totalchunks,
							sliceoffset, slicelength);

		expectedchunk++;
	}

	if (versioned)
	{
		char	   *chunkdata_ver = NULL;
		int32		chunksize_ver = 0;

		if (visibility_check(visibility_cxt, &chunkdata_ver, &chunksize_ver, NULL))
		{
			chunkdata_ver += header_size;
			chunksize_ver -= header_size;

			process_toast_chunk(toastrel, valueid, result, chunk_data_size, attrsize,
								chunksize_ver, chunkdata_ver, expectedchunk,
								expectedchunk, startchunk, endchunk, totalchunks,
								sliceoffset, slicelength);
			expectedchunk++;
		}
	}

	/*
	 * Final checks that we successfully fetched the datum
	 */
	if (expectedchunk != (endchunk + 1))
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("missing chunk number %d for toast value %u in %s",
								 expectedchunk, valueid,
								 RelationGetRelationName(toastrel))));

	/* End scan and close indexes. */
	systable_endscan_ordered(toastscan);
	toast_close_indexes(toastidxs, num_indexes, AccessShareLock);
}

void
toast_update_datum(Datum value,
				   void *slice_data, int slice_offset, int slice_length,
				   void *chunk_header, int chunk_header_size,
				   ToastChunkVisibilityCheck visibility_check,
				   void *visibility_cxt, int options)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	struct varatt_external toast_pointer;
	Relation	toastrel;
	Relation   *toastidxs;
	int			num_indexes;
	int			validIndex;

	Assert(VARATT_IS_EXTERNAL_ONDISK(attr));

	/* Must copy to access aligned fields */
	VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

	/* Open the toast relation and its indexes */
	toastrel = table_open(toast_pointer.va_toastrelid, RowExclusiveLock);

	/* Fetch valid relation used for process */
	validIndex = toast_open_indexes(toastrel,
									RowExclusiveLock,
									&toastidxs,
									&num_indexes);

	toast_write_slice(toastrel, toastidxs, num_indexes, validIndex,
					  toast_pointer.va_valueid,
					  VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer),
					  slice_offset, slice_length, slice_data,
					  options, chunk_header, chunk_header_size,
					  visibility_check, visibility_cxt);

	toast_close_indexes(toastidxs, num_indexes, NoLock);
	table_close(toastrel, NoLock);
}

static void *
toast_fetch_old_chunk(Relation toastrel, SysScanDesc toastscan, Oid valueid,
					  int32 expected_chunk_seq, int32 last_old_chunk_seq,
					  ToastChunkVisibilityCheck visibility_check,
					  void *visibility_cxt,
					  int32 *p_old_chunk_size, ItemPointer old_tid)
{
	for (;;)
	{
		HeapTuple	old_toasttup;
		char	   *old_chunk_data;
		int32		old_chunk_seq;
		int32		old_chunk_data_size;

		old_toasttup = systable_getnext_ordered(toastscan, ForwardScanDirection);

		if (old_toasttup)
		{
			/* Skip aborted chunks */
			if (!HeapTupleHeaderXminCommitted(old_toasttup->t_data))
			{
				TransactionId xmin = HeapTupleHeaderGetXmin(old_toasttup->t_data);

				Assert(!HeapTupleHeaderXminInvalid(old_toasttup->t_data));

				if (TransactionIdDidAbort(xmin))
					continue;
			}

			toast_extract_chunk_fields(toastrel, toastrel->rd_att,
									   valueid, old_toasttup,
									   &old_chunk_seq,
									   &old_chunk_data,
									   &old_chunk_data_size);
		}

		if (!old_toasttup || old_chunk_seq != expected_chunk_seq)
		{
			/*
			 * All versions of the current chunk were processed,
			 * select a visible one and use it.
			 */
			char	   *chunkdata = NULL;

			if (!visibility_check(visibility_cxt, &chunkdata,
								  p_old_chunk_size, old_tid))
				ereport(ERROR,
						(errcode(ERRCODE_DATA_CORRUPTED),
						 errmsg_internal("missing chunk number %d for toast value %u in %s",
										 expected_chunk_seq, valueid,
										 RelationGetRelationName(toastrel))));

			if (old_toasttup ?
				old_chunk_seq != expected_chunk_seq + 1 :
				expected_chunk_seq != last_old_chunk_seq)
				ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg_internal("missing chunk number %d for toast value %u in %s",
									 expected_chunk_seq + 1, valueid,
									 RelationGetRelationName(toastrel))));

			return chunkdata;
		}

		visibility_check(visibility_cxt,
						 &old_chunk_data,
						 &old_chunk_data_size,
						 &old_toasttup->t_self);
	}
}

static void
toast_write_slice(Relation toastrel, Relation *toastidxs,
				  int num_indexes, int validIndex,
				  Oid valueid, int32 value_size, int32 slice_offset,
				  int32 slice_length, char *slice_data, int options,
				  void *chunk_header, int chunk_header_size,
				  ToastChunkVisibilityCheck visibility_check,
				  void *visibility_cxt)
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
	int32		max_chunks_size = TOAST_MAX_CHUNK_SIZE - chunk_header_size;
	int32		chunk_size;
	int32		chunk_seq = slice_offset / max_chunks_size;
	int32		chunk_offset = chunk_seq * max_chunks_size;
	int32		last_old_chunk_seq = (value_size - 1) / max_chunks_size;
	Datum		t_values[3];
	bool		t_isnull[3];

	ScanKeyData toastkey[2];
	SysScanDesc toastscan = NULL;
	SnapshotData SnapshotToast;

	if (chunk_offset < value_size)
	{
		/*
		 * Setup a scan key to find chunks with matching va_valueid
		 */
		ScanKeyInit(&toastkey[0],
					(AttrNumber) 1,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(valueid));

		ScanKeyInit(&toastkey[1],
					(AttrNumber) 2,
					BTGreaterEqualStrategyNumber, F_INT4GE,
					Int32GetDatum(chunk_seq));

		/*
		 * Find all the chunks.  (We don't actually care whether we see them in
		 * sequence or not, but since we've already locked the index we might as
		 * well use systable_beginscan_ordered.)
		 */
		init_toast_snapshot(&SnapshotToast);
		toastscan = systable_beginscan_ordered(toastrel, toastidxs[validIndex],
											   &SnapshotToast, 2, toastkey);
	}

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
		ItemPointerData old_tid = {0};
		int32		old_chunk_size = chunk_offset >= value_size ? 0 :
			Min(max_chunks_size, value_size - chunk_offset);
		int32		chunk_slice_start = slice_offset <= chunk_offset ?
			0 : slice_offset - chunk_offset;
		int32		copied_slice_size =
			Min(max_chunks_size - chunk_slice_start, slice_length);
		bool		rewrite_chunk =
			(slice_offset > chunk_offset &&
			 slice_offset < chunk_offset + max_chunks_size) ||
			slice_length < old_chunk_size;
		bool		is_update = toastscan && chunk_seq <= last_old_chunk_seq;

		CHECK_FOR_INTERRUPTS();

		/* Fetch old tuple and copy its data */
		if (is_update)
		{
			int32		old_chunk_size_hdr;
			void	   *old_chunk_data =
				toast_fetch_old_chunk(toastrel, toastscan, valueid,
									  chunk_seq, last_old_chunk_seq,
									  visibility_check, visibility_cxt,
									  &old_chunk_size_hdr,
									  &old_tid);

			Assert(old_chunk_size == old_chunk_size_hdr - chunk_header_size);

			if (rewrite_chunk)
				memcpy(VARDATA(&chunk_data), old_chunk_data, old_chunk_size_hdr);
		}

		/*
		 * Calculate the size of this chunk
		 */
		copied_slice_size = Min(max_chunks_size - chunk_slice_start, slice_length);
		chunk_size = Max(old_chunk_size, chunk_slice_start + copied_slice_size);

		/*
		 * Build a tuple and store it
		 */
		t_values[1] = Int32GetDatum(chunk_seq++);
		SET_VARSIZE(&chunk_data, chunk_size + chunk_header_size + VARHDRSZ);
		if (chunk_header_size > 0)
			memcpy(VARDATA(&chunk_data), chunk_header, chunk_header_size);
		memcpy(VARDATA(&chunk_data) + chunk_slice_start + chunk_header_size, slice_data, copied_slice_size);
		toasttup = heap_form_tuple(toasttupDesc, t_values, t_isnull);

		if (is_update)
		{
			TM_Result	result;
			TM_FailureData tmfd;
			LockTupleMode lockmode;

			result = heap_update(toastrel, &old_tid, toasttup,
								 mycid, InvalidSnapshot,
								 true, /* wait for commit */
								 &tmfd, &lockmode);

			switch (result)
			{
				case TM_Ok:
					/* done successfully */
					break;

				case TM_SelfModified:
					elog(ERROR, "TOAST tuple already updated by self");
					break;

				case TM_Updated:
					elog(ERROR, "TOAST tuple concurrently updated");
					break;

				case TM_Deleted:
					elog(ERROR, "TOAST tuple concurrently deleted");
					break;

				default:
					elog(ERROR, "unrecognized heap_update status: %u", result);
					break;
			}
		}
		else
			heap_insert(toastrel, toasttup, mycid, options, NULL);


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

	if (toastscan)
		systable_endscan_ordered(toastscan);
}

static void
toast_extract_chunk_fields(Relation toastrel, TupleDesc toasttupDesc,
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

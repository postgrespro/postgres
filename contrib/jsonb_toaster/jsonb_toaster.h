/*-------------------------------------------------------------------------
 *
 * jsonb_toaster.h
 *
 * Copyright (c) 2022, PostgresPro
 *
 * IDENTIFICATION
 *	  contrib/jsonb_toaster/jsonb_toaster.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef JSONB_TOASTER_H

#include "postgres.h"

typedef struct JsonxFetchDatumIteratorData
{
	ToastBuffer	*buf;
	Relation	toastrel;
	Relation	*toastidxs;
	MemoryContext mcxt;
	SysScanDesc	toastscan;
	ScanKeyData	toastkey[2];
	SnapshotData snapshot;
	struct varatt_external toast_pointer;
	int32		ressize;
	int32		nextidx;
	int32		chunksize;
	int32		numchunks;
	int			valid_index;
	int			num_indexes;
	bool		done;

	bool		compressed_chunks;
	char	   *chunks_bitmap;
	ItemPointer	chunk_tids;
	void	   *compressed_chunk_tids;
	int			nchunk_tids;
	int			chunk_tids_inline_size;
	Oid			toasterid;

	struct IndexFetchTableData *heapfetch;
	struct TupleTableSlot *slot;
	bool		cached;
}				JsonxFetchDatumIteratorData;

typedef struct JsonxFetchDatumIteratorData *JsonxFetchDatumIterator;

typedef struct JsonxDetoastIteratorData
{
	GenericDetoastIteratorData gen;
	ToastBuffer 		*buf;
	JsonxFetchDatumIterator	fetch_datum_iterator;
	int					nrefs;
	void			   *decompression_state;
	ToastCompressionId	compression_method;
	bool				compressed;		/* toast value is compressed? */
	bool				done;
}			JsonxDetoastIteratorData;

typedef struct JsonxDetoastIteratorData *JsonxDetoastIterator;

extern Datum jsonx_toast_save_datum(Relation rel, Datum value,
									struct varlena *oldexternal,
									int options);
extern Datum
jsonx_toast_save_datum_ext(Relation rel, Oid toasterid, Datum value,
					 struct varlena *oldexternal, int options,
					 struct varlena **p_chunk_tids);
extern void jsonx_toast_delete_datum(Datum value, bool is_speculative);

extern JsonxDetoastIterator jsonx_create_detoast_iterator(struct varlena *attr);
extern void jsonx_free_detoast_iterator(JsonxDetoastIterator iter);
extern void jsonx_detoast_iterate(JsonxDetoastIterator detoast_iter,
								  const char *destend);
extern void jsonx_detoast_iterate_slice(JsonxDetoastIterator detoast_iter,
										int32 offset, int32 length);
extern struct varlena *jsonx_toast_compress_tids(struct varlena *chunk_tids,
												 int max_size);


/*
 * Support for de-TOASTing toasted value iteratively. "need" is a pointer
 * between the beginning and end of iterator's ToastBuffer. The marco
 * de-TOAST all bytes before "need" into iterator's ToastBuffer.
 */
#define JSONX_DETOAST_ITERATE(iter, need)										\
	do {																		\
		Assert((need) >= (iter)->buf->buf && (need) <= (iter)->buf->capacity);	\
		while (!(iter)->done && (need) > (iter)->buf->limit) { 					\
			jsonx_detoast_iterate(iter, need);									\
		}																		\
	} while (0)

#if 0
#define JSONX_DETOAST_ITERATE_SLICE(iter, offset, length) \
		JSONX_DETOAST_ITERATE(iter, (iter)->buf->buf + (offset) + (length))
#else
#define JSONX_DETOAST_ITERATE_SLICE(iter, offset, length)						\
	do {																		\
		const char *need = (iter)->buf->buf + (offset) + (length);				\
		Assert(offset >= 0);													\
		Assert(length > 0);														\
		Assert(need <= (iter)->buf->capacity);									\
		if ((iter)->compressed)													\
			JSONX_DETOAST_ITERATE(iter, need);									\
		else																	\
			jsonx_detoast_iterate_slice(iter, offset, length);					\
	} while (0)
#endif

#endif /* JSONB_TOASTER_H */

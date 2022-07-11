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
#include "utils/jsonb.h"
#include "utils/jsonb_internals.h"

#define JSONX_POINTER_TYPE_MASK				0xF0000000
#define JSONX_PLAIN_JSONB					0x00000000
#define JSONX_POINTER						0x10000000
#define JSONX_POINTER_DIRECT_TIDS			0x20000000
#define JSONX_POINTER_DIRECT_TIDS_COMP		0x30000000
#define JSONX_POINTER_COMPRESSED_CHUNKS		0x40000000
#define JSONX_POINTER_DIFF					0x50000000
#define JSONX_POINTER_DIFF_COMP				0x60000000
#define JSONX_CHUCKED_ARRAY					0x70000000

#define JSONX_CUSTOM_PTR_HEADER_SIZE		(INTALIGN(VARATT_CUSTOM_SIZE(0)) + sizeof(uint32))

#define JSONX_CUSTOM_PTR_GET_HEADER(ptr)	(*(uint32*)((char *) (ptr) + INTALIGN(VARATT_CUSTOM_SIZE(0))))
#define JSONX_CUSTOM_PTR_GET_DATA(ptr)		((char *) (ptr) + JSONX_CUSTOM_PTR_HEADER_SIZE)
#define JSONX_CUSTOM_PTR_GET_DATA_SIZE(ptr)	(VARATT_CUSTOM_SIZE(VARATT_CUSTOM_GET_DATA_SIZE(ptr)) - JSONX_CUSTOM_PTR_HEADER_SIZE)

typedef struct JsonxCompressedChunk
{
	ToastBuffer	src_buf;
	ToastBuffer	dst_buf;
	void	   *decompression_state;
	ToastCompressionId compression_method;
	int32		offset;
	int32		size;
} JsonxCompressedChunk;

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

	JsonxCompressedChunk compressed_chunk;

	struct IndexFetchTableData *heapfetch;
	struct TupleTableSlot *slot;
	bool		cached;
}				JsonxFetchDatumIteratorData;

typedef struct JsonxFetchDatumIteratorData *JsonxFetchDatumIterator;

typedef struct JsonxDetoastIteratorData
{
	GenericDetoastIteratorData gen;
	ToastBuffer 		*buf;
	ToastBuffer 		*orig_buf;
	JsonxFetchDatumIterator	fetch_datum_iterator;
	struct
	{
		const char *data;
		const char *inline_data;
		int32		inline_size;
		int32		size;
		int32		offset;
	}					diff;
	int					nrefs;
	void			   *decompression_state;
	ToastCompressionId	compression_method;
	bool				compressed;		/* toast value is compressed? */
	bool				done;
}			JsonxDetoastIteratorData;

typedef struct JsonxDetoastIteratorData *JsonxDetoastIterator;

typedef struct JsonbToastedContainerPointerData
{
	struct varlena *toast_ptr;
	const void *tail_data;
	struct varatt_external ptr;
	uint32		tail_size;
	uint32		container_offset;
	Oid			toasterid;
	uint32		ntids;
	bool		compressed_tids;
	bool		compressed_chunks;
	bool		has_diff;
} JsonbToastedContainerPointerData;

typedef struct JsonxPointerDiff
{
	int32		offset;
	char		data[FLEXIBLE_ARRAY_MEMBER];
} JsonxPointerDiff;

#define JSONXA_INLINE_CHUNK 0x80000000

typedef ItemPointerData JsonxArrayChunkPtr;
typedef uint32 JsonxArrayChunkOffset;

typedef struct JsonxArray
{
	int32		n_elems;
	int32		n_chunks;
	Oid			toastrelid;
	JsonxArrayChunkOffset	chunk_offsets[FLEXIBLE_ARRAY_MEMBER];
	/* JsonxArrayChunkPtr	chunk_ptrs[FLEXIBLE_ARRAY_MEMBER]; */
} JsonxArray;

#define JSONX_ARRAY_HDR_SIZE \
	(JSONX_CUSTOM_PTR_HEADER_SIZE + offsetof(JsonxArray, chunk_offsets))

#define JSONX_ARRAY_SIZE(n_chunks) \
	(JSONX_ARRAY_HDR_SIZE + \
	 (sizeof(JsonxArrayChunkOffset) + sizeof(JsonxArrayChunkPtr)) * (n_chunks))

#define JSONX_ARRAY_CHUNK_PTRS(jxa) \
	((JsonxArrayChunkPtr *) &(jxa)->chunk_offsets[(jxa)->n_chunks])

typedef struct JsonxArrayChunkInfo
{
	Datum		jb;
	JsonxArrayChunkOffset offset;
	JsonxArrayChunkPtr ptr;
} JsonxArrayChunkInfo;

extern JsonContainerOps jsonxaContainerOps;
extern void jsonxaInit(JsonContainerData *jc, Datum value);

extern Datum jsonx_toast_save_datum(Relation rel, Datum value,
									struct varlena *oldexternal,
									int options);
extern Datum
jsonx_toast_save_datum_ext(Relation rel, Oid toasterid, Datum value,
					 struct varlena *oldexternal, int options,
					 struct varlena **p_chunk_tids,
					 ItemPointerData *chunk_tids,
					 bool compress_chunks);
extern void jsonx_toast_delete_datum(Datum value, bool is_speculative);

extern JsonxDetoastIterator jsonx_create_detoast_iterator(struct varlena *attr);
extern void jsonx_free_detoast_iterator(JsonxDetoastIterator iter);
extern void jsonx_detoast_iterate(JsonxDetoastIterator detoast_iter,
								  const char *destend);
extern void jsonx_detoast_iterate_slice(JsonxDetoastIterator detoast_iter,
										int32 offset, int32 length);

extern struct varlena *
jsonx_toast_make_plain_pointer(Oid toasterid, JsonbContainerHeader *jbc, int len);

extern struct varlena *
jsonx_toast_make_pointer_diff(Oid toasterid, struct varatt_external *ptr,
							  bool compressed_chunks,
							  int32 diff_offset, int32 diff_len,
							  const void *diff_data);

extern struct varlena *
jsonx_toast_make_pointer_array(Oid toasterid, int n_chunks, int inline_chunks_size,
							   JsonxArray **p_array);

extern struct varlena *
jsonx_toast_wrap_array_into_pointer(Oid toasterid, JsonxArray *array,
									int data_size);

extern struct varlena *
jsonx_toast_compress_tids(struct varlena *chunk_tids, int max_size);

extern char *
jsonxWriteCustomToastPointerHeader(char *ptr, Oid toasterid, uint32 header,
								   int datalen, int rawsize);

extern void
jsonxInitToastedContainerPointer(JsonbToastedContainerPointerData *jbcptr,
								 varatt_external *toast_ptr,
								 uint32 tail_size, const void *tail_data,
								 int ntids, bool compressed_tids,
								 bool compressed_chunks,
								 Oid toasterid, uint32 container_offset);

extern bool
jsonxInitToastedContainerPointerFromIterator(JsonxFetchDatumIterator fetch_iter,
											 JsonbToastedContainerPointerData *jbcptr,
											 uint32 container_offset);

extern struct varlena *
jsonxMakeToastPointer(JsonbToastedContainerPointerData *ptr);

extern void
jsonxWriteToastPointer(StringInfo buffer, JsonbToastedContainerPointerData *ptr);

extern int
jsonxToastPointerSize(JsonbToastedContainerPointerData *jbcptr_data);

extern bool
jsonb_toaster_save_array(Relation rel, Oid toasterid, JsonContainer *root,
						 Size max_size, char cmethod, int options, Datum *res);

extern void jsonxa_toaster_delete(JsonContainer *jc, bool is_speculative);
extern Datum jsonxa_toaster_copy(Relation rel, Oid toasterid,
								 JsonContainer *jc, char cmethod);
extern Datum jsonxa_toaster_cmp(Relation rel, Oid toasterid,
								JsonContainer *new_jc,
								JsonContainer *old_jc, char cmethod);


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

/*-------------------------------------------------------------------------
 *
 * detoast.h
 *	  Access to compressed and external varlena values.
 *
 * Copyright (c) 2000-2021, PostgreSQL Global Development Group
 *
 * src/include/access/detoast.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef DETOAST_H
#define DETOAST_H

#include "access/toast_compression.h"

/*
 * Macro to fetch the possibly-unaligned contents of an EXTERNAL datum
 * into a local "struct varatt_external" toast pointer.  This should be
 * just a memcpy, but some versions of gcc seem to produce broken code
 * that assumes the datum contents are aligned.  Introducing an explicit
 * intermediate "varattrib_1b_e *" variable seems to fix it.
 */
#define VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	Assert(VARATT_IS_EXTERNAL(attre)); \
	Assert(VARSIZE_EXTERNAL(attre) == sizeof(toast_pointer) + VARHDRSZ_EXTERNAL); \
	memcpy(&(toast_pointer), VARDATA_EXTERNAL(attre), sizeof(toast_pointer)); \
} while (0)

static inline Size
varatt_external_inline_get_pointer(struct varlena *attr, /* FIXME */
								   struct varatt_external *toast_pointer)
{
	if (VARATT_IS_EXTERNAL_ONDISK_INLINE(attr))
	{
		struct varatt_external_inline toast_pointer_inline;

		memcpy(&toast_pointer_inline, VARDATA_EXTERNAL(attr),
			   sizeof(toast_pointer_inline));
		*toast_pointer = toast_pointer_inline.va_external;

		return toast_pointer_inline.va_inline_size;
	}
	else
	{
		VARATT_EXTERNAL_GET_POINTER(*toast_pointer, attr);
		return 0;
	}
}

#define VARATT_EXTERNAL_INLINE_GET_POINTER(toast_ptr, attr) \
	varatt_external_inline_get_pointer(attr, &(toast_ptr))


/* Size of an EXTERNAL datum that contains a standard TOAST pointer */
#define TOAST_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_external))
#define TOAST_INLINE_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_external_inline))

/* Size of an EXTERNAL datum that contains an indirection pointer */
#define INDIRECT_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_indirect))

/* ----------
 * detoast_external_attr() -
 *
 *		Fetches an external stored attribute from the toast
 *		relation. Does NOT decompress it, if stored external
 *		in compressed format.
 * ----------
 */
extern struct varlena *detoast_external_attr(struct varlena *attr);

/* ----------
 * detoast_attr() -
 *
 *		Fully detoasts one attribute, fetching and/or decompressing
 *		it as needed.
 * ----------
 */
extern struct varlena *detoast_attr(struct varlena *attr);

/* ----------
 * detoast_attr_slice() -
 *
 *		Fetches only the specified portion of an attribute.
 *		(Handles all cases for attribute storage)
 * ----------
 */
extern struct varlena *detoast_attr_slice(struct varlena *attr,
										  int32 sliceoffset,
										  int32 slicelength);

#ifndef FRONTEND
#include "access/genam.h"

/*
 * TOAST buffer is a producer consumer buffer.
 *
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |  |  |  |  |  |  |  |  |  |  |  |  |  |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    ^           ^           ^              ^
 *   buf      position      limit         capacity
 *
 * buf: point to the start of buffer.
 * position: point to the next char to be consumed.
 * limit: point to the next char to be produced.
 * capacity: point to the end of buffer.
 *
 * Constraints that need to be satisfied:
 * buf <= position <= limit <= capacity
 */
typedef struct ToastBuffer
{
	const char	*buf;
	const char	*position;
	char		*limit;
	const char	*capacity;
} ToastBuffer;

typedef struct FetchDatumIteratorData
{
	ToastBuffer	*buf;
	Relation	toastrel;
	Relation	*toastidxs;
	MemoryContext mcxt;
	SysScanDesc	toastscan;
	ScanKeyData	toastkey;
	SnapshotData			snapshot;
	struct varatt_external toast_pointer;
	int32		ressize;
	int32		nextidx;
	int32		numchunks;
	int			num_indexes;
	int			tail_size;
	bool		done;
}				FetchDatumIteratorData;

typedef struct FetchDatumIteratorData *FetchDatumIterator;

typedef struct DetoastIteratorData
{
	ToastBuffer 		*buf;
	FetchDatumIterator	fetch_datum_iterator;
	int					nrefs;
	void			   *decompression_state;
	ToastCompressionId	compression_method;
	bool				compressed;		/* toast value is compressed? */
	bool				done;
}			DetoastIteratorData;

typedef struct DetoastIteratorData *DetoastIterator;

extern FetchDatumIterator create_fetch_datum_iterator(struct varlena *attr);
extern void free_fetch_datum_iterator(FetchDatumIterator iter);
extern void fetch_datum_iterate(FetchDatumIterator iter);
extern ToastBuffer *create_toast_buffer(int32 size, bool compressed);
extern void free_toast_buffer(ToastBuffer *buf);
extern void toast_decompress_iterate(ToastBuffer *source, ToastBuffer *dest,
									 DetoastIterator iter, const char *destend);
extern void pglz_decompress_iterate(ToastBuffer *source, ToastBuffer *dest,
									DetoastIterator iter, char *destend);

/* ----------
 * create_detoast_iterator -
 *
 * It only makes sense to initialize a de-TOAST iterator for external on-disk values.
 *
 * ----------
 */
extern DetoastIterator create_detoast_iterator(struct varlena *attr);

/* ----------
 * free_detoast_iterator -
 *
 * Free memory used by the de-TOAST iterator, including buffers and
 * fetch datum iterator.
 * ----------
 */
extern void free_detoast_iterator(DetoastIterator iter);

/* ----------
 * detoast_iterate -
 *
 * Iterate through the toasted value referenced by iterator.
 *
 * As long as there is another data chunk in external storage,
 * de-TOAST it into iterator's toast buffer.
 * ----------
 */
static inline void
detoast_iterate(DetoastIterator detoast_iter, const char *destend)
{
	FetchDatumIterator fetch_iter = detoast_iter->fetch_datum_iterator;

	Assert(detoast_iter != NULL && !detoast_iter->done && fetch_iter);

	if (!detoast_iter->compressed)
		destend = NULL;

	if (1 && destend)
	{
		const char *srcend = (const char *)
			(fetch_iter->buf->limit == fetch_iter->buf->capacity ?
			fetch_iter->buf->limit : fetch_iter->buf->limit - 4);

		if (fetch_iter->buf->position >= srcend && !fetch_iter->done)
			fetch_datum_iterate(fetch_iter);
	}
	else if (!fetch_iter->done)
		fetch_datum_iterate(fetch_iter);

	if (detoast_iter->compressed)
		toast_decompress_iterate(fetch_iter->buf, detoast_iter->buf, detoast_iter, destend);

	if (detoast_iter->buf->limit == detoast_iter->buf->capacity)
	{
		detoast_iter->done = true;
#if 0
		if (detoast_iter->buf == fetch_iter->buf)
			fetch_iter->buf = NULL;
		free_fetch_datum_iterator(fetch_iter);
		detoast_iter->fetch_datum_iterator = NULL;
#endif
	}
}


#endif

/* ----------
 * toast_raw_datum_size -
 *
 *	Return the raw (detoasted) size of a varlena datum
 * ----------
 */
extern Size toast_raw_datum_size(Datum value);

/* ----------
 * toast_datum_size -
 *
 *	Return the storage size of a varlena datum
 * ----------
 */
extern Size toast_datum_size(Datum value);

#endif							/* DETOAST_H */

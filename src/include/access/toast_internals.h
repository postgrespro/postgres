/*-------------------------------------------------------------------------
 *
 * toast_internals.h
 *	  Internal definitions for the TOAST system.
 *
 * Copyright (c) 2000-2023, PostgreSQL Global Development Group
 *
 * src/include/access/toast_internals.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOAST_INTERNALS_H
#define TOAST_INTERNALS_H

#include "access/toast_compression.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"
#include "utils/snapshot.h"
#include "utils/rel.h"
#include "access/table.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "utils/expandeddatum.h"
/*
 *	The information at the start of the compressed toast data.
 */
typedef struct toast_compress_header
{
	int32		vl_len_;		/* varlena header (do not touch directly!) */
	uint32		tcinfo;			/* 2 bits for compression method and 30 bits
								 * external size; see va_extinfo */
} toast_compress_header;

/*
 * Utilities for manipulation of header information for compressed
 * toast entries.
 */
#define TOAST_COMPRESS_EXTSIZE(ptr) \
	(((toast_compress_header *) (ptr))->tcinfo & VARLENA_EXTSIZE_MASK)
#define TOAST_COMPRESS_METHOD(ptr) \
	(((toast_compress_header *) (ptr))->tcinfo >> VARLENA_EXTSIZE_BITS)

#define TOAST_COMPRESS_SET_SIZE_AND_COMPRESS_METHOD(ptr, len, cm_method) \
	do { \
		Assert((len) > 0 && (len) <= VARLENA_EXTSIZE_MASK); \
		Assert((cm_method) == TOAST_PGLZ_COMPRESSION_ID || \
			   (cm_method) == TOAST_LZ4_COMPRESSION_ID); \
		((toast_compress_header *) (ptr))->tcinfo = \
			(len) | ((uint32) (cm_method) << VARLENA_EXTSIZE_BITS); \
	} while (0)

/* extern Datum toast_compress_datum(Datum value, char cmethod); */
extern bool toastrel_valueid_exists(Relation toastrel, Oid valueid);
extern bool toastid_valueid_exists(Oid toastrelid, Oid valueid);

extern void toast_delete_datum(Datum value, bool is_speculative);
extern Datum toast_save_datum(Relation rel, Datum value,
							  struct varlena *oldexternal, int options);
extern Datum toast_save_datum_ext(Relation rel, Datum value,
								  struct varlena *oldexternal, int options,
								  void *chunk_header, int chunk_header_size);

typedef bool (*ToastChunkVisibilityCheck)(void *cxt, char **chunkdata,
										  int32 *chunksize,
										  ItemPointer tid);

extern struct varlena *toast_fetch_datum(struct varlena *attr);
extern struct varlena *toast_fetch_datum_slice(struct varlena *attr,
											   int32 sliceoffset,
											   int32 slicelength);

extern void
toast_fetch_toast_slice(Relation toastrel, Oid valueid,
						struct varlena *attr, int32 attrsize,
						int32 sliceoffset, int32 slicelength,
						struct varlena *result, int32 header_size,
						ToastChunkVisibilityCheck visibility_check,
						void *visibility_cxt);

extern void
toast_update_datum(Datum value,
				   void *slice_data, int slice_offset, int slice_length,
				   void *chunk_header, int chunk_header_size,
				   ToastChunkVisibilityCheck visibility_check,
				   void *visibility_cxt, int options);

#endif							/* TOAST_INTERNALS_H */

/*-------------------------------------------------------------------------
 *
 * toast_extended.h
 *	  Internal definitions for the TOAST system.
 *
 * Copyright (c) 2000-2022, PostgreSQL Global Development Group
 *
 * src/include/access/toast_extended.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOAST_EXTENDED_H
#define TOAST_EXTENDED_H

#include "access/toast_internals.h"
#include "access/toast_compression.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"
#include "utils/snapshot.h"
#include "utils/rel.h"
#include "access/table.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "utils/expandeddatum.h"

typedef bool (*ToastChunkVisibilityCheck)(void *cxt, char **chunkdata,
										  int32 *chunksize,
										  ItemPointer tid);

extern Datum toast_save_datum_ext(Relation rel, Oid toasteroid, Datum value,
								  struct varlena *oldexternal, int options, int attnum,
								  void *chunk_header, int chunk_header_size);

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

#endif							/* TOAST_EXTENDED_H */

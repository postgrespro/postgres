/*-------------------------------------------------------------------------
 *
 * toast_extended.h
 *	  Internal definitions for the bytea appendable toaster.
 *
 * Copyright (c) 2000-2022, PostgreSQL Global Development Group
 *
 * contrib/bytea_toaster/toast_extended.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOAST_EXTENDED_H
#define TOAST_EXTENDED_H

#include "postgres.h"

#include "utils/rel.h"
#include "storage/itemptr.h"

typedef bool (*ToastChunkVisibilityCheck)(void *cxt, char **chunkdata,
										  int32 *chunksize,
										  ItemPointer tid);

extern Datum toast_save_datum_ext(Relation rel, Oid toastrelid, Oid toasteroid, Datum value,
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

extern void
toast_delete_datum_ext(Relation rel, Datum value, bool is_speculative,
					   int32 header_size,
					   ToastChunkVisibilityCheck visibility_check,
					   void *visibility_cxt);

#endif							/* TOAST_EXTENDED_H */

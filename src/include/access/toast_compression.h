/*-------------------------------------------------------------------------
 *
 * toast_compression.h
 *	  Functions for toast compression.
 *
 * Copyright (c) 2021-2023, PostgreSQL Global Development Group
 *
 * src/include/access/toast_compression.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef TOAST_COMPRESSION_H
#define TOAST_COMPRESSION_H

#include "access/toast_iterator.h"

/*
 * GUC support.
 *
 * default_toast_compression is an integer for purposes of the GUC machinery,
 * but the value is one of the char values defined below, as they appear in
 * pg_attribute.attcompression, e.g. TOAST_PGLZ_COMPRESSION.
 */
extern PGDLLIMPORT int default_toast_compression;

/*
 * Built-in compression methods.  pg_attribute will store these in the
 * attcompression column.  In attcompression, InvalidCompressionMethod
 * denotes the default behavior.
 */
#define TOAST_PGLZ_COMPRESSION			'p'
#define TOAST_LZ4_COMPRESSION			'l'
#define InvalidCompressionMethod		'\0'

#define CompressionMethodIsValid(cm)  ((cm) != InvalidCompressionMethod)

/* Opaque pglz decompression state */
typedef struct pglz_state
{
	int32		len;
	int32		off;
	int			ctrlc;
	unsigned char ctrl;
} pglz_state;

/* pglz compression/decompression routines */
extern struct varlena *pglz_compress_datum(const struct varlena *value);
extern struct varlena *pglz_decompress_datum(const struct varlena *value);
extern struct varlena *pglz_decompress_datum_slice(const struct varlena *value,
												   int32 slicelength);

/* lz4 compression/decompression routines */
extern struct varlena *lz4_compress_datum(const struct varlena *value);
extern struct varlena *lz4_decompress_datum(const struct varlena *value);
extern struct varlena *lz4_decompress_datum_slice(const struct varlena *value,
												  int32 slicelength);

/* other stuff */
extern ToastCompressionId toast_get_compression_id(struct varlena *attr);
extern char CompressionNameToMethod(const char *compression);
extern const char *GetCompressionMethodName(char method);

extern void pglz_decompress_iterate(ToastBuffer *source, ToastBuffer *dest,
									DetoastIterator iter, char *destend);

extern int32
pglz_decompress_state(const char *source, int32 *slen, char *dest,
					  int32 dlen, bool check_complete, bool last_cource_chunk,
					  void **pstate);

#endif							/* TOAST_COMPRESSION_H */

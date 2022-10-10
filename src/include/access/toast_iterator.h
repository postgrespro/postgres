/*-------------------------------------------------------------------------
 *
 * toast_iterator.h
 *	  Functions for toast compression.
 *
 * Copyright (c) 2021-2022, PostgreSQL Global Development Group
 *
 * src/include/access/toast_iterator.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef TOAST_ITERATOR_H
#define TOAST_ITERATOR_H

#include "postgres.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/toast_internals.h"
#include "access/heapam.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"

/*
 * Built-in compression method ID.  The toast compression header will store
 * this in the first 2 bits of the raw length.  These built-in compression
 * method IDs are directly mapped to the built-in compression methods.
 *
 * Don't use these values for anything other than understanding the meaning
 * of the raw bits from a varlena; in particular, if the goal is to identify
 * a compression method, use the constants TOAST_PGLZ_COMPRESSION, etc.
 * below. We might someday support more than 4 compression methods, but
 * we can never have more than 4 values in this enum, because there are
 * only 2 bits available in the places where this is stored.
 */
typedef enum ToastCompressionId
{
	TOAST_PGLZ_COMPRESSION_ID = 0,
	TOAST_LZ4_COMPRESSION_ID = 1,
	TOAST_INVALID_COMPRESSION_ID = 2
} ToastCompressionId;

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
	bool		done;
}				FetchDatumIteratorData;

typedef struct FetchDatumIteratorData *FetchDatumIterator;

typedef struct GenericDetoastIteratorData
{
	MemoryContextCallback free_callback;
} GenericDetoastIteratorData, *GenericDetoastIterator;

typedef struct DetoastIteratorData *DetoastIterator;

typedef struct DetoastIteratorData
{
	GenericDetoastIteratorData gen;
	ToastBuffer 		*buf;
	FetchDatumIterator	fetch_datum_iterator;
	DetoastIterator	   *self_ptr;
	int					nrefs;
	void			   *decompression_state;
	ToastCompressionId	compression_method;
	bool				compressed;		/* toast value is compressed? */
	bool				done;
}			DetoastIteratorData;

#define NO_LZ4_SUPPORT() \
	ereport(ERROR, \
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED), \
			 errmsg("compression method lz4 not supported"), \
			 errdetail("This functionality requires the server to be built with lz4 support.")))
#endif /* TOAST_ITERATOR_H */
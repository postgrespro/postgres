#ifndef GENERIC_TOASTER_H
#define GENERIC_TOASTER_H
#include "postgres.h"
#include "fmgr.h"
#include "access/toasterapi.h"
#include "access/toasterapi.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "catalog/pg_toaster.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
#include "access/xact.h"
#include "catalog/binary_upgrade.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "storage/lock.h"
#include "utils/rel.h"
#include "access/relation.h"
#include "access/table.h"
#include "access/toast_internals.h"
#include "access/heapam.h"
#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/toast_helper.h"
#include "utils/fmgroids.h"

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
	char	*buf;
	char	*position;
	char		*limit;
	char	*capacity;
} ToastBuffer;

typedef struct FetchDatumIteratorData
{
	ToastBuffer	*buf;
	Relation	toastrel;
	Relation	*toastidxs;
	SysScanDesc	toastscan;
	ScanKeyData	toastkey;
	SnapshotData			snapshot;
	struct varatt_external	toast_pointer;
	int32		ressize;
	int32		nextidx;
	int32		numchunks;
	int			num_indexes;
	bool		done;
}				FetchDatumIteratorData;

typedef struct FetchDatumIteratorData *FetchDatumIterator;

/*
 * If "ctrlc" field in iterator is equal to INVALID_CTRLC, it means that
 * the field is invalid and need to read the control byte from the
 * source buffer in the next iteration, see pglz_decompress_iterate().
 */
#define INVALID_CTRLC 8

typedef struct DetoastIteratorData
{
	ToastBuffer 		*buf;
	FetchDatumIterator	fetch_datum_iterator;
	unsigned char		ctrl;
	int					ctrlc;
	bool				compressed;		/* toast value is compressed? */
	bool				done;
}			DetoastIteratorData;

typedef struct DetoastIteratorData *DetoastIterator;

typedef struct GenericToastRoutine
{
       int32           magic;
       DetoastIterator 	(*init_detoast_iterator)(struct varlena *attr);
	   void     	(*detoast_iterate_next)(DetoastIterator detoast_iter, char *need);
} GenericToastRoutine;

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
 * "need" is a pointer between the beginning and end of iterator's
 * ToastBuffer, de-TOAST all bytes before "need" into iterator's ToastBuffer.
 * ----------
 */
extern void detoast_iterate(DetoastIterator detoast_iter, char *need);

FetchDatumIterator
create_fetch_datum_iterator(struct varlena *attr);

ToastBuffer *
create_toast_buffer(int32 size, bool compressed);

void
free_toast_buffer(ToastBuffer *buf);

void
free_fetch_datum_iterator(FetchDatumIterator iter);

void
pglz_decompress_iterate(ToastBuffer *source, ToastBuffer *dest, DetoastIterator iter);

void
free_toast_buffer(ToastBuffer *buf);

void
fetch_datum_iterate(FetchDatumIterator iter);

extern struct varlena *
generic_toaster_reconstruct(Relation toastrel, struct varlena *varlena,
                            HTAB *toast_hash);
#endif

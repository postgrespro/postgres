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
#include "access/toast_iterator.h"

extern FetchDatumIterator create_fetch_datum_iterator(struct varlena *attr);
extern void free_fetch_datum_iterator(FetchDatumIterator iter);
extern void fetch_datum_iterate(FetchDatumIterator iter);
extern ToastBuffer *create_toast_buffer(int32 size, bool compressed);
extern void free_toast_buffer(ToastBuffer *buf);
extern void toast_decompress_iterate(ToastBuffer *source, ToastBuffer *dest,
									 ToastCompressionId compression_method,
									 void **decompression_state,
									 const char *destend);

extern void free_detoast_iterator_resources(DetoastIterator iter);

extern Datum generic_iterator_create(Datum value);
extern void generic_iterate_next(Datum detoast_iter, Datum buf);

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

	Assert(detoast_iter != NULL && !detoast_iter->done);

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
		toast_decompress_iterate(fetch_iter->buf, detoast_iter->buf,
								 detoast_iter->compression_method,
								 &detoast_iter->decompression_state,
								 destend);

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

#define GENERIC_TOASTER_MAGIC    0xb17ea758

typedef struct GenericToastRoutine
{
	int32		magic;
	Datum	  (*detoast_iterator_create)(Datum value);
	void	  (*detoast_iterate_next)(Datum detoast_iter, Datum destend);
} GenericToastRoutine;

extern struct varlena *
generic_toaster_reconstruct(Relation toastrel, struct varlena *varlena,
                            HTAB *toast_hash);
#endif

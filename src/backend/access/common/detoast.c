/*-------------------------------------------------------------------------
 *
 * detoast.c
 *	  Retrieve compressed or external variable size attributes.
 *
 * Copyright (c) 2000-2022, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/common/detoast.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/detoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/toast_internals.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "utils/expandeddatum.h"
#include "utils/rel.h"
#include "access/toasterapi.h"

/* ----------
 * create_detoast_iterator -
 *
 * It only makes sense to initialize a de-TOAST iterator for external on-disk values.
 *
 * ----------
 */
DetoastIterator
create_detoast_iterator(struct varlena *attr)
{
	struct varatt_external toast_pointer;
	DetoastIterator iter;
	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		FetchDatumIterator fetch_iter;

		iter = (DetoastIterator) palloc0(sizeof(DetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;

		/* This is an externally stored datum --- initialize fetch datum iterator */
		iter->fetch_datum_iterator = fetch_iter = create_fetch_datum_iterator(attr);
		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);
		if (VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
		{
			iter->compressed = true;
			iter->compression_method = VARATT_EXTERNAL_GET_COMPRESS_METHOD(toast_pointer);

			/* prepare buffer to received decompressed data */
			iter->buf = create_toast_buffer(toast_pointer.va_rawsize, false);
		}
		else
		{
			iter->compressed = false;
			iter->compression_method = TOAST_INVALID_COMPRESSION_ID;

			/* point the buffer directly at the raw data */
			iter->buf = fetch_iter->buf;
		}
		return iter;
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		/* indirect pointer --- dereference it */
		struct varatt_indirect redirect;

		VARATT_EXTERNAL_GET_POINTER(redirect, attr);
		attr = (struct varlena *) redirect.pointer;

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(attr));

		/* recurse in case value is still extended in some other way */
		return create_detoast_iterator(attr);

	}
	else if (1 && VARATT_IS_COMPRESSED(attr))
	{
		ToastBuffer *buf;

		iter = (DetoastIterator) palloc0(sizeof(DetoastIteratorData));
		iter->done = false;
		iter->nrefs = 1;

		iter->fetch_datum_iterator = palloc0(sizeof(*iter->fetch_datum_iterator));
		iter->fetch_datum_iterator->buf = buf = create_toast_buffer(VARSIZE_ANY(attr), true);
		iter->fetch_datum_iterator->done = true;
		iter->compressed = true;
		iter->compression_method = VARDATA_COMPRESSED_GET_COMPRESS_METHOD(attr);

		memcpy((void *) buf->buf, attr, VARSIZE_ANY(attr));
		buf->limit = (char *) buf->capacity;

		/* prepare buffer to received decompressed data */
		iter->buf = create_toast_buffer(TOAST_COMPRESS_EXTSIZE(attr) + VARHDRSZ, false);

		return iter;
	}
	else
		/* in-line value -- no iteration used, even if it's compressed */
		return NULL;
}

/* ----------
 * free_detoast_iterator -
 *
 * Free memory used by the de-TOAST iterator, including buffers and
 * fetch datum iterator.
 * ----------
 */
void
free_detoast_iterator(DetoastIterator iter)
{
	if (iter == NULL)
		return;
	if (--iter->nrefs > 0)
		return;
	if (iter->compressed)
		free_toast_buffer(iter->buf);
	free_fetch_datum_iterator(iter->fetch_datum_iterator);
	pfree(iter);
}

/*-------------------------------------------------------------------------
 *
 * bytea_toaster.c
 *		Appendable bytea toaster.
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/bytea_toaster/bytea_toaster.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/toasterapi.h"
#include "access/toast_helper.h"
#include "access/toast_internals.h"
#include "catalog/toasting.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

typedef uint64 AppendableToastVersion;

#define BYTEA_INVALID_VERSION	0
#define BYTEA_FIRST_VERSION		1

typedef struct AppendableToastData
{
	varatt_external ptr;
	AppendableToastVersion version;
	int32		inline_tail_size;
	char	   *inline_tail_data; /* [FLEXIBLE_ARRAY_MEMBER]; */
} AppendableToastData;

#define VARATT_CUSTOM_APPENDABLE_HDRSZ \
	offsetof(AppendableToastData, inline_tail_data)

#define VARATT_CUSTOM_APPENDABLE_SIZE(inline_size) \
	VARATT_CUSTOM_SIZE(VARATT_CUSTOM_APPENDABLE_HDRSZ + (inline_size))

#define VARATT_CUSTOM_GET_APPENDABLE_DATA(attr, data) \
do { \
	varattrib_1b_e *attrc = (varattrib_1b_e *)(attr); \
	Assert(VARATT_IS_CUSTOM(attrc)); \
	Assert(VARSIZE_CUSTOM(attrc) >= VARATT_CUSTOM_APPENDABLE_SIZE(0)); \
	memcpy(&(data), VARATT_CUSTOM_GET_DATA(attrc), VARATT_CUSTOM_APPENDABLE_HDRSZ); \
	(data).inline_tail_data = VARATT_CUSTOM_GET_DATA(attrc) + VARATT_CUSTOM_APPENDABLE_HDRSZ; \
} while (0)

static void
bytea_toaster_init(Relation rel, Oid toastoid, Oid toastindexoid, Datum reloptions, LOCKMODE lockmode,
				   bool check, Oid OIDOldToast)
{
	(void) create_toast_table(rel, InvalidOid, InvalidOid, reloptions,
							  lockmode, check, OIDOldToast);
}

static bool
bytea_toaster_validate(Oid typeoid, char storage, char compression,
					   Oid amoid, bool false_ok)

{
	return typeoid == BYTEAOID &&
		storage == TYPSTORAGE_EXTERNAL &&
		compression == TOAST_INVALID_COMPRESSION_ID;
}

static struct varlena *
bytea_toaster_make_pointer(Oid toasterid, struct varatt_external *ptr,
						   AppendableToastVersion version,
						   Size inline_tail_size, char **pdata)
{
	Size		size = VARATT_CUSTOM_APPENDABLE_SIZE(inline_tail_size);
	struct varlena *result = palloc(size);
	AppendableToastData result_data;

	SET_VARTAG_EXTERNAL(result, VARTAG_CUSTOM);

	if (ptr->va_rawsize + inline_tail_size > MaxAllocSize)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("atribute length too large")));

	VARATT_CUSTOM_SET_TOASTERID(result, toasterid);
	VARATT_CUSTOM_SET_DATA_RAW_SIZE(result, ptr->va_rawsize + inline_tail_size);
	VARATT_CUSTOM_SET_DATA_SIZE(result, VARATT_CUSTOM_APPENDABLE_HDRSZ + inline_tail_size);

	result_data.ptr = *ptr;
	result_data.version = version;
	result_data.inline_tail_size = inline_tail_size;

	memcpy(VARATT_CUSTOM_GET_DATA(result), &result_data, VARATT_CUSTOM_APPENDABLE_HDRSZ);

	if (pdata)
		*pdata = VARATT_CUSTOM_GET_DATA(result) + VARATT_CUSTOM_APPENDABLE_HDRSZ;

	return result;
}

typedef struct AppendableToastVisibilityContext
{
	char		chunkdata[BLCKSZ];
	Size		chunksize;
	ItemPointerData chunktid;
	AppendableToastVersion max_chunk_version;
	AppendableToastVersion attrversion;
} AppendableToastVisibilityContext;

static bool
bytea_toaster_check_visibility(void *pcxt, char **chunkdata,
							   int32 *chunksize, ItemPointer tid)
{
	AppendableToastVisibilityContext *cxt = pcxt;
	AppendableToastVersion chunkversion;

	if (!*chunkdata)
	{
		if (!cxt->chunksize)
			return false;

		*chunkdata = cxt->chunkdata;
		*chunksize = cxt->chunksize;
		if (tid)
			*tid = cxt->chunktid;

		cxt->max_chunk_version = BYTEA_INVALID_VERSION;
		cxt->chunksize = 0;

		return true;
	}

	Assert(*chunksize > sizeof(chunkversion));
	memcpy(&chunkversion, *chunkdata, sizeof(chunkversion));

	if (chunkversion <= cxt->attrversion &&
		(cxt->max_chunk_version == BYTEA_INVALID_VERSION ||
		 cxt->max_chunk_version < chunkversion))
	{
		cxt->max_chunk_version = chunkversion;
		cxt->chunksize = *chunksize;

		Assert(*chunksize <= sizeof(cxt->chunkdata));
		memcpy(cxt->chunkdata, *chunkdata, *chunksize);

		if (tid)
			cxt->chunktid = *tid;
	}

	return false;
}

static void
bytea_toaster_delete_toast(Datum oldval, bool is_speculative)
{
	if (VARATT_IS_CUSTOM(oldval))
	{
		AppendableToastData old_data;
		char		ptr[TOAST_POINTER_SIZE];

		VARATT_CUSTOM_GET_APPENDABLE_DATA(oldval, old_data);

		SET_VARTAG_EXTERNAL(ptr, VARTAG_ONDISK);
		memcpy(VARDATA_EXTERNAL(ptr), &old_data.ptr, sizeof(old_data.ptr));

		toast_delete_datum(PointerGetDatum(ptr), is_speculative);
	}
}

static Datum
bytea_toaster_copy(Relation rel, Oid toasterid, Datum newval, int options)
{
	Datum		detoasted_newval;
	Datum		toasted_newval;
	struct varatt_external toast_ptr;
	AppendableToastVersion version = BYTEA_FIRST_VERSION;

	detoasted_newval = PointerGetDatum(detoast_attr((struct varlena *) newval));
	toasted_newval = toast_save_datum_ext(rel, detoasted_newval,
										  NULL, options,
										  &version, sizeof(version));

	Assert(VARATT_IS_EXTERNAL_ONDISK(toasted_newval));
	VARATT_EXTERNAL_GET_POINTER(toast_ptr, DatumGetPointer(toasted_newval));

	pfree(DatumGetPointer(toasted_newval));

	return PointerGetDatum(bytea_toaster_make_pointer(toasterid, &toast_ptr, version, 0, NULL));
}

static Datum
bytea_toaster_toast(Relation rel, Oid toasterid,
					Datum newval, Datum oldval,
					int max_inline_size, int options)
{
	return PointerGetDatum(bytea_toaster_copy(rel, toasterid, newval, options));
}

static Datum
bytea_toaster_update_toast(Relation rel, Oid toasterid,
						   Datum newval, Datum oldval, int options)
{
	bool		is_speculative = false; /* (options & HEAP_INSERT_SPECULATIVE) != 0 XXX */

	if (VARATT_IS_CUSTOM(newval) && VARATT_IS_CUSTOM(oldval))
	{
		AppendableToastData old_data;
		AppendableToastData new_data;
		Oid			toastrelid = rel->rd_rel->reltoastrelid;

		VARATT_CUSTOM_GET_APPENDABLE_DATA(oldval, old_data);
		VARATT_CUSTOM_GET_APPENDABLE_DATA(newval, new_data);

		if (new_data.ptr.va_toastrelid == toastrelid &&
			new_data.ptr.va_toastrelid == old_data.ptr.va_toastrelid &&
			new_data.ptr.va_valueid == old_data.ptr.va_valueid &&
			new_data.version == old_data.version &&
			memcmp(&old_data.ptr, &new_data.ptr, sizeof(old_data.ptr)) == 0)
		{
			char		ptr[TOAST_POINTER_SIZE];
			Size		toasted_size = VARATT_EXTERNAL_GET_EXTSIZE(old_data.ptr);
			AppendableToastVisibilityContext cxt = {0};
			AppendableToastVersion version = new_data.version + 1;
			struct varatt_external toast_ptr = new_data.ptr;

			cxt.max_chunk_version = BYTEA_INVALID_VERSION;
			cxt.attrversion = old_data.version;

			SET_VARTAG_EXTERNAL(ptr, VARTAG_ONDISK);
			memcpy(VARDATA_EXTERNAL(ptr), &toast_ptr, sizeof(toast_ptr));

			toast_update_datum(PointerGetDatum(ptr),
							   new_data.inline_tail_data,
							   toasted_size,
							   new_data.inline_tail_size,
							   &version, sizeof(version),
							   bytea_toaster_check_visibility, &cxt, options);

			VARATT_EXTERNAL_SET_SIZE_AND_COMPRESS_METHOD(toast_ptr, toasted_size + new_data.inline_tail_size, 0);

			return PointerGetDatum(bytea_toaster_make_pointer(toasterid, &toast_ptr, version, 0, NULL));
		}
	}

	if (VARATT_IS_CUSTOM(oldval))
		bytea_toaster_delete_toast(oldval, is_speculative);
	else if (VARATT_IS_EXTERNAL_ONDISK(oldval))
		toast_delete_datum(oldval, is_speculative);

	return PointerGetDatum(bytea_toaster_copy(rel, toasterid, newval, options));
}

static Datum
bytea_toaster_copy_toast(Relation rel, Oid toasterid,
						 Datum newval, int options)
{
	return PointerGetDatum(bytea_toaster_copy(rel, toasterid, newval, options));
}

static Datum
bytea_toaster_detoast(Datum toastptr,
					  int sliceoffset, int slicelength)
{
	AppendableToastData data;
	struct varlena *result;
	int32		attrsize;
	int32		inline_size;
	int32		toasted_size;

	Assert(VARATT_IS_CUSTOM(toastptr));
	VARATT_CUSTOM_GET_APPENDABLE_DATA(toastptr, data);

	toasted_size = VARATT_EXTERNAL_GET_EXTSIZE(data.ptr);
	inline_size = data.inline_tail_size;

	attrsize = toasted_size + inline_size;

	if (sliceoffset >= attrsize)
	{
		sliceoffset = 0;
		slicelength = 0;
	}

	/*
	 * When fetching a prefix of a compressed external datum, account for the
	 * space required by va_tcinfo, which is stored at the beginning as an
	 * int32 value.
	 */
	if (VARATT_EXTERNAL_IS_COMPRESSED(data.ptr) && slicelength > 0)
		slicelength = slicelength + sizeof(int32);

	/*
	 * Adjust length request if needed.  (Note: our sole caller,
	 * detoast_attr_slice, protects us against sliceoffset + slicelength
	 * overflowing.)
	 */
	if (((sliceoffset + slicelength) > attrsize) || slicelength < 0)
		slicelength = attrsize - sliceoffset;

	result = (struct varlena *) palloc(slicelength + VARHDRSZ);

	if (VARATT_EXTERNAL_IS_COMPRESSED(data.ptr))
		SET_VARSIZE_COMPRESSED(result, slicelength + VARHDRSZ);
	else
		SET_VARSIZE(result, slicelength + VARHDRSZ);

	if (sliceoffset + slicelength > attrsize - inline_size)
	{
		int32		size = Min(sliceoffset + slicelength - (attrsize - inline_size), inline_size);
		int32		inline_offset = Max(0, sliceoffset - (attrsize - inline_size));

		size = Min(size, slicelength);

		memcpy(VARDATA(result) + slicelength - size,
			   data.inline_tail_data + inline_offset, size);

		slicelength -= size;
	}

	if (slicelength > 0)
	{
		AppendableToastVisibilityContext cxt = {0};
		Relation toastrel;

		cxt.max_chunk_version = BYTEA_INVALID_VERSION;
		cxt.attrversion = data.version;

		toastrel = table_open(data.ptr.va_toastrelid, AccessShareLock);

		toast_fetch_toast_slice(toastrel, data.ptr.va_valueid,
								(struct varlena *) toastptr,	/* XXX */
								toasted_size, sliceoffset, slicelength,
								result, sizeof(AppendableToastVersion),
								bytea_toaster_check_visibility, &cxt);

		table_close(toastrel, AccessShareLock);
	}

	return PointerGetDatum(result);
}

static Datum
bytea_toaster_append(Datum d1, Datum d2)
{
	bytea	   *t1;
	bytea	   *t2 = DatumGetByteaPP(d2);

	if (VARATT_IS_CUSTOM(d1))
	{
		AppendableToastData t1_data;
		char	   *t2_data = VARDATA_ANY(t2);
		int32		t2_size = VARSIZE_ANY_EXHDR(t2);
		Oid			toasterid = VARATT_CUSTOM_GET_TOASTERID(d1);

		VARATT_CUSTOM_GET_APPENDABLE_DATA(d1, t1_data);

		/* Simply append inline TOAST data if not compressed */
		if (!VARATT_EXTERNAL_IS_COMPRESSED(t1_data.ptr))
		{
			char	   *res_inline_tail_data;
			struct varlena *result =
				bytea_toaster_make_pointer(toasterid, &t1_data.ptr,
										   t1_data.version,
										   (Size) t1_data.inline_tail_size + t2_size,
										   &res_inline_tail_data);

			if (t1_data.inline_tail_size)
				memcpy(res_inline_tail_data,
					   t1_data.inline_tail_data,
					   t1_data.inline_tail_size);

			memcpy(res_inline_tail_data + t1_data.inline_tail_size,
				   t2_data, t2_size);

			return PointerGetDatum(result);
		}
	}

	t1 = DatumGetByteaPP(d1);

	return DirectFunctionCall2(byteacat, PointerGetDatum(t1), PointerGetDatum(t2));
}

static void *
bytea_toaster_vtable(Datum toast_ptr)
{
	ByteaToastRoutine *routine = palloc0(sizeof(*routine));

	routine->magic = BYTEA_TOASTER_MAGIC;
	routine->append = bytea_toaster_append;

	return routine;
}

PG_FUNCTION_INFO_V1(bytea_toaster_handler);
Datum
bytea_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsr = makeNode(TsrRoutine);

	tsr->init = bytea_toaster_init;
	tsr->toast = bytea_toaster_toast;
	tsr->deltoast = bytea_toaster_delete_toast;
	tsr->copy_toast = bytea_toaster_copy_toast;
	tsr->update_toast = bytea_toaster_update_toast;
	tsr->detoast = bytea_toaster_detoast;
	tsr->toastervalidate = bytea_toaster_validate;
	tsr->get_vtable = bytea_toaster_vtable;

	PG_RETURN_POINTER(tsr);
}

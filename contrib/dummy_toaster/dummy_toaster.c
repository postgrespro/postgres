/*-------------------------------------------------------------------------
 *
 * dummy_toaster.c
 *		Dummy toaster utilities.
 *
 * Portions Copyright (c) 2016-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1990-1993, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/dummy_toaster/dummy_toaster.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "fmgr.h"
#include "access/toasterapi.h"
#include "nodes/makefuncs.h"

PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(dummy_toaster_handler);

typedef struct varatt_dummy_toaster
{
	varatt_external	toast_ptr;
	char *data_buffer;
} varatt_dummy_toaster;

#define VARATT_DUMMY_HDRSZ \
	offsetof(varatt_custom, va_toasterdata)

#define VARATT_DUMMY_TOASTER_GET_DATA(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	memcpy(&(toast_pointer), VARATT_CUSTOM_GET_DATA(attre), VARATT_DUMMY_HDRSZ); \
	((varatt_custom)(toast_pointer)).va_toasterdata = VARATT_CUSTOM_GET_DATA(attre) + VARATT_DUMMY_HDRSZ; \
} while (0)

#define VARDATA_DUMMY(PTR)	(((varattrib_1b_e *) (PTR)) + VARATT_DUMMY_HDRSZ)

#define DUMMY_TOAST_MAX_CHUNK_SIZE	\
	(EXTERN_TUPLE_MAX_SIZE -							\
	 MAXALIGN(SizeofHeapTupleHeader) -					\
	 sizeof(Oid) -										\
	 sizeof(int32) -									\
	 sizeof(int32) -									\
	 VARATT_DUMMY_HDRSZ)


/* Size of an EXTERNAL datum that contains a custom TOAST pointer */
#define DUMMY_TOAST_POINTER_SIZE (VARHDRSZ_EXTERNAL + sizeof(varatt_dummy_toaster))

#define VARATT_IS_DUMMY(PTR) \
	(VARATT_IS_EXTERNAL(PTR) && VARTAG_EXTERNAL(PTR) == VARTAG_CUSTOM)
#define MAX_DUMMY_CHUNK_SIZE 2048

/*
 * Dummy Detoast function, receives single varatt_custom pointer,
 * detoasts it to varlena.
 *
 */
Datum
dummyDetoast(Relation toast_rel,
								Datum toast_ptr,
								int offset, int length)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	struct varlena *result = 0;// = palloc(VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen));
	struct varatt_custom *customPtr;

	Assert(VARATT_IS_EXTERNAL(attr));
	Assert(VARATT_IS_CUSTOM(attr));

	customPtr = palloc(VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen));
	memcpy(customPtr, attr, (VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen)));

	/* Create regular varlena and return */
	if((((varatt_custom *)(attr))->va_toasterdatalen) > MAX_DUMMY_CHUNK_SIZE)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds MAX_DUMMY_CHUNK_SIZE <%d>",
				 				 (((varatt_custom *)(attr))->va_toasterdatalen),
								 MAX_DUMMY_CHUNK_SIZE)));
		
	}
	memcpy(VARDATA(result), (((varatt_custom *)(attr))->va_toasterdata), 
		(((varatt_custom *)(attr))->va_toasterdatalen));
	pfree(customPtr);
	return PointerGetDatum(result);
}

/*
 * Dummy Toast function, receives varlena pointer, creates single varatt_custom
 * varlena size is limited to 1024 bytes
 */

Datum
dummyToast(Relation toast_rel,
								Datum value, Datum oldvalue,
								int max_inline_size)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	struct varatt_custom *dptr = palloc(VARHDRSZ_EXTERNAL + ((varatt_custom *)(attr))->va_rawsize);
	struct varlena *result = 0; 
	int l_offset = 0;
	int l_length = 0;
	int cpy_size = 0;
	int counter = 0;
	struct varatt_custom *new_ptr;

	Assert(VARATT_IS_EXTERNAL(attr));
	Assert(VARATT_IS_CUSTOM(attr));

	if((((varatt_custom *)(attr))->va_toasterdatalen) > MAX_DUMMY_CHUNK_SIZE)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds MAX_DUMMY_CHUNK_SIZE <%d>",
				 				 (((varatt_custom *)(attr))->va_toasterdatalen),
								 MAX_DUMMY_CHUNK_SIZE)));
		
	}

	memcpy(dptr, VARATT_CUSTOM_GET_DATA(attr), ((varatt_custom *)(attr))->va_toasterdatalen);
		return PointerGetDatum(result);

	if(VARATT_IS_EXTERNAL(attr))
	{
		memcpy(dptr, (attr + VARHDRSZ_EXTERNAL), ((varatt_external *)(attr))->va_rawsize);
		dptr->va_version = 1;
		dptr->va_toasterdatalen = (((varatt_external *)(attr))->va_rawsize);
		memcpy(result, dptr, sizeof(*dptr));
		return PointerGetDatum(result);
	}
	else
	{
		PG_RETURN_VOID();
	}
}

/*
 * Dummy Validate, always returns True
 * 
 */

bool
dummyToasterValidate(Oid toasteroid, Oid typeoid,  Oid amoid, bool false_ok)
{
	PG_RETURN_VOID();
}


Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);
	tsrroutine->toast = dummyToast;
	tsrroutine->detoast = dummyDetoast;
	tsrroutine->get_vtable = dummyGetVtable;
	tsrroutine->toastervalidate = dummyToasterValidate;
	PG_RETURN_POINTER(tsrroutine);
}

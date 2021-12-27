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


#define VARATT_DUMMY_GET_POINTER(toast_pointer, attr) \
do { \
	varattrib_1b_e *attre = (varattrib_1b_e *) (attr); \
	Assert(VARATT_IS_CUSTOM(attre)); \
	Assert(VARSIZE_EXTERNAL(attre) == sizeof(toast_pointer) + VARHDRSZ_EXTERNAL); \
	memcpy(&(toast_pointer), VARDATA_EXTERNAL(attre), sizeof(toast_pointer)); \
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
#define MAX_DUMMY_CHUNK_SIZE 1024

static void
dummyToastInit(Relation rel, Datum reloptions, LOCKMODE lockmode,
				 bool check, Oid OIDOldToast)
{
	(void) create_toast_table(rel, InvalidOid, InvalidOid, reloptions, lockmode,
							  check, OIDOldToast);
}

/*
 * Dummy Detoast function, receives single varatt_custom pointer,
 * detoasts it to varlena.
 *
 */
<<<<<<< HEAD
Datum
dummyDetoast(Relation toast_rel,
								Datum toast_ptr,
								int offset, int length)
=======
static struct varlena*
dummyDetoast(Datum toast_ptr,
				int offset, int length)
>>>>>>> Dummy minor changes
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(toast_ptr);
	struct varlena *result = palloc(VARATT_DUMMY_HDRSZ + (((varatt_custom *)(attr))->va_toasterdatalen));

	Assert(VARATT_IS_EXTERNAL(attr));
	Assert(VARATT_IS_CUSTOM(attr));
	/* Create regular varlena and return */
	if(VARATT_CUSTOM_GET_DATA_SIZE(attr) > MAX_DUMMY_CHUNK_SIZE)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds MAX_DUMMY_CHUNK_SIZE <%d>",
				 				 (((varatt_custom *)(attr))->va_toasterdatalen),
								 MAX_DUMMY_CHUNK_SIZE)));
		
	}
	SET_VARSIZE(result, VARATT_CUSTOM_GET_DATA_SIZE(attr) + VARHDRSZ);
	memcpy(VARDATA(result), VARATT_CUSTOM_GET_DATA(attr), VARATT_CUSTOM_GET_DATA_SIZE(attr));

	return result;
}

/*
 * Dummy Toast function, receives varlena pointer, creates single varatt_custom
 * varlena size is limited to 1024 bytes
 */

static struct varlena*
dummyToast(Relation toast_rel,
					Datum value, Datum oldvalue,
					int max_inline_size)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	/* struct varatt_custom *dptr = palloc(VARATT_CUSTOM_SIZE(VARATT_CUSTOM_GET_DATA_SIZE(attr)));*/
	/* struct varlena *result = 0;  */

	Assert(VARATT_IS_EXTERNAL(attr));
	Assert(VARATT_IS_CUSTOM(attr));

	if(VARATT_CUSTOM_GET_DATA_SIZE(attr) > MAX_DUMMY_CHUNK_SIZE)
	{
		ereport(ERROR,
				(errcode(ERRCODE_DATA_CORRUPTED),
				 errmsg_internal("Data <%d> size exceeds MAX_DUMMY_CHUNK_SIZE <%d>",
				 				 (((varatt_custom *)(attr))->va_toasterdatalen),
								 MAX_DUMMY_CHUNK_SIZE)));
		
	}
	PG_RETURN_VOID();
/*
	memcpy(dptr, VARATT_CUSTOM_GET_DATA(attr), VARATT_CUSTOM_GET_DATA_SIZE(attr));
		return PointerGetDatum(dptr); */
}

/*
 * Dummy Validate, always returns True
 * 
 */

bool
dummyToasterValidate(Oid toasteroid)
{
<<<<<<< HEAD
	bool result = true;

	return result;
}

<<<<<<< HEAD
	memcpy(VARATT_CUSTOM_GET_DATA(result), &result_data, VARATT_DUMMY_HDRSZ);

	if (pdata)
		*pdata = VARATT_CUSTOM_GET_DATA(result) + VARATT_DUMMY_HDRSZ;

	return result;
=======
	TsrRoutine  *tsr = makeNode(TsrRoutine);

	PG_RETURN_POINTER(tsr);
>>>>>>>  use validateToster call
}
*/
=======
>>>>>>> Dummy toaster and default through new API

Datum
dummy_toaster_handler(PG_FUNCTION_ARGS)
{
	TsrRoutine *tsrroutine = makeNode(TsrRoutine);
	tsrroutine->init = dummyToastInit;
	tsrroutine->toast = dummyToast;
	tsrroutine->detoast = dummyDetoast;
	tsrroutine->get_vtable = dummyGetVtable;
	tsrroutine->toastervalidate = dummyToasterValidate;
	PG_RETURN_POINTER(tsrroutine);
}

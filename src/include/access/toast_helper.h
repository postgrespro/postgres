/*-------------------------------------------------------------------------
 *
 * toast_helper.h
 *	  Helper functions for table AMs implementing compressed or
 *    out-of-line storage of varlena attributes.
 *
 * Copyright (c) 2000-2023, PostgreSQL Global Development Group
 *
 * src/include/access/toast_helper.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef TOAST_HELPER_H
#define TOAST_HELPER_H

#include "utils/rel.h"
#include "access/toasterapi.h"
#include "access/toast_internals.h"
#include "access/table.h"
#include "access/tableam.h"
#include "common/int.h"
#include "common/pg_lzcompress.h"
#include "utils/expandeddatum.h"

/*
 * Information about one column of a tuple being toasted.
 *
 * NOTE: toast_action[i] can have these values:
 *		' '						default handling
 *		TYPSTORAGE_PLAIN		already processed --- don't touch it
 *		TYPSTORAGE_EXTENDED		incompressible, but OK to move off
 *
 * NOTE: toast_attr[i].tai_size is only made valid for varlena attributes with
 * toast_action[i] different from TYPSTORAGE_PLAIN.
 */
typedef struct
{
	struct varlena *tai_oldexternal;
	int32		tai_size;
	uint8		tai_colflags;
	char		tai_compression;
	TsrRoutine *tai_toaster;
	Oid			tai_toasterid;
} ToastAttrInfo;

/*
 * Information about one tuple being toasted.
 */
typedef struct
{
	/*
	 * Before calling toast_tuple_init, the caller must initialize the
	 * following fields.  Each array must have a length equal to
	 * ttc_rel->rd_att->natts.  The tts_oldvalues and tts_oldisnull fields
	 * should be NULL in the case of an insert.
	 */
	Relation	ttc_rel;		/* the relation that contains the tuple */
	Datum	   *ttc_values;		/* values from the tuple columns */
	bool	   *ttc_isnull;		/* null flags for the tuple columns */
	Datum	   *ttc_oldvalues;	/* values from previous tuple */
	bool	   *ttc_oldisnull;	/* null flags from previous tuple */

	/*
	 * Before calling toast_tuple_init, the caller should set tts_attr to
	 * point to an array of ToastAttrInfo structures of a length equal to
	 * tts_rel->rd_att->natts.  The contents of the array need not be
	 * initialized.  ttc_flags also does not need to be initialized.
	 */
	uint8		ttc_flags;
	ToastAttrInfo *ttc_attr;
} ToastTupleContext;

/*
 * Flags indicating the overall state of a TOAST operation.
 *
 * TOAST_NEEDS_DELETE_OLD indicates that one or more old TOAST datums need
 * to be deleted.
 *
 * TOAST_NEEDS_FREE indicates that one or more TOAST values need to be freed.
 *
 * TOAST_HAS_NULLS indicates that nulls were found in the tuple being toasted.
 *
 * TOAST_NEEDS_CHANGE indicates that a new tuple needs to built; in other
 * words, the toaster did something.
 */
#define TOAST_NEEDS_DELETE_OLD				0x0001
#define TOAST_NEEDS_FREE					0x0002
#define TOAST_HAS_NULLS						0x0004
#define TOAST_NEEDS_CHANGE					0x0008

/*
 * Flags indicating the status of a TOAST operation with respect to a
 * particular column.
 *
 * TOASTCOL_NEEDS_DELETE_OLD indicates that the old TOAST datums for this
 * column need to be deleted.
 *
 * TOASTCOL_NEEDS_FREE indicates that the value for this column needs to
 * be freed.
 *
 * TOASTCOL_IGNORE indicates that the toaster should not further process
 * this column.
 *
 * TOASTCOL_INCOMPRESSIBLE indicates that this column has been found to
 * be incompressible, but could be moved out-of-line.
 */
#define TOASTCOL_NEEDS_DELETE_OLD			TOAST_NEEDS_DELETE_OLD
#define TOASTCOL_NEEDS_FREE					TOAST_NEEDS_FREE
#define TOASTCOL_IGNORE						0x0010
#define TOASTCOL_INCOMPRESSIBLE				0x0020

extern void toast_tuple_init(ToastTupleContext *ttc);
extern int	toast_tuple_find_biggest_attribute(ToastTupleContext *ttc,
											   bool for_compression,
											   bool check_main);
extern void toast_tuple_try_compression(ToastTupleContext *ttc, int attribute);
extern void toast_tuple_externalize(ToastTupleContext *ttc, int attribute,
									int maxDataLen, int options);
extern void toast_tuple_cleanup(ToastTupleContext *ttc);

extern void toast_delete_external(Relation rel, Datum *values, bool *isnull,
								  bool is_speculative);

extern Datum toast_compress_datum(Datum value, char cmethod);
extern struct varlena *toast_decompress_datum(struct varlena *attr);
extern struct varlena *toast_decompress_datum_slice(struct varlena *attr, int32 slicelength);

/* ----------
 * detoast_external_attr() -
 *
 *		Fetches an external stored attribute from the toast
 *		relation. Does NOT decompress it, if stored external
 *		in compressed format.
 * ----------
 */
extern struct varlena *detoast_external_attr(struct varlena *attr);

/* ----------
 * detoast_attr() -
 *
 *		Fully detoasts one attribute, fetching and/or decompressing
 *		it as needed.
 * ----------
 */
extern struct varlena *detoast_attr(struct varlena *attr);

/* ----------
 * detoast_attr_slice() -
 *
 *		Fetches only the specified portion of an attribute.
 *		(Handles all cases for attribute storage)
 * ----------
 */
extern struct varlena *detoast_attr_slice(struct varlena *attr,
										  int32 sliceoffset,
										  int32 slicelength);


/* ----------
 * toast_raw_datum_size -
 *
 *	Return the raw (detoasted) size of a varlena datum
 * ----------
 */
extern Size toast_raw_datum_size(Datum value);

/* ----------
 * toast_datum_size -
 *
 *	Return the storage size of a varlena datum
 * ----------
 */
extern Size toast_datum_size(Datum value);

extern void
fetch_toast_slice(Relation toastrel, Oid valueid, 
					   struct varlena *attr, int32 attrsize,
					   int32 sliceoffset, int32 slicelength,
					   struct varlena *result);

#endif

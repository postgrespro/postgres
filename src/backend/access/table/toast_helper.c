/*-------------------------------------------------------------------------
 *
 * toast_helper.c
 *	  Helper functions for table AMs implementing compressed or
 *    out-of-line storage of varlena attributes.
 *
 * Copyright (c) 2000-2023, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/table/toast_helper.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/toasterapi.h"
#include "access/table.h"
#include "access/toast_helper.h"
#include "access/toast_internals.h"
#include "catalog/pg_type_d.h"
#include "varatt.h"
#include "catalog/pg_toaster_d.h"
#include "access/heaptoast.h"

/*
 * Prepare to TOAST a tuple.
 *
 * tupleDesc, toast_values, and toast_isnull are required parameters; they
 * provide the necessary details about the tuple to be toasted.
 *
 * toast_oldvalues and toast_oldisnull should be NULL for a newly-inserted
 * tuple; for an update, they should describe the existing tuple.
 *
 * All of these arrays should have a length equal to tupleDesc->natts.
 *
 * On return, toast_flags and toast_attr will have been initialized.
 * toast_flags is just a single uint8, but toast_attr is a caller-provided
 * array with a length equal to tupleDesc->natts.  The caller need not
 * perform any initialization of the array before calling this function.
 */
void
toast_tuple_init(ToastTupleContext *ttc)
{
	TupleDesc	tupleDesc = ttc->ttc_rel->rd_att;
	int			numAttrs = tupleDesc->natts;
	int			i;

	ttc->ttc_flags = 0;

	for (i = 0; i < numAttrs; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);
		struct varlena *old_value;
		struct varlena *new_value;
		TsrRoutine *toaster;
		Oid			toasterid;
		bool		need_detoast = true;

		ttc->ttc_attr[i].tai_colflags = 0;
		ttc->ttc_attr[i].tai_oldexternal = NULL;
		ttc->ttc_attr[i].tai_compression = att->attcompression;

		toasterid = att->atttoaster;
		toaster = OidIsValid(toasterid) ?
			SearchTsrCache(att->atttoaster) : NULL;

		ttc->ttc_attr[i].tai_toaster = toaster;
		ttc->ttc_attr[i].tai_toasterid = toasterid;

		if (ttc->ttc_oldvalues != NULL)
		{
			/*
			 * For UPDATE get the old and new values of this attribute
			 */
			old_value =
				(struct varlena *) DatumGetPointer(ttc->ttc_oldvalues[i]);
			new_value =
				(struct varlena *) DatumGetPointer(ttc->ttc_values[i]);

			/*
			 * If the old value is stored on disk, check if it has changed so
			 * we have to delete it later.
			 */
			if (att->attlen == -1 && !ttc->ttc_oldisnull[i] &&
				(VARATT_IS_EXTERNAL_ONDISK(old_value) || VARATT_IS_CUSTOM(old_value)))
			{
				if (ttc->ttc_isnull[i] ||
					!(VARATT_IS_EXTERNAL_ONDISK(new_value) || VARATT_IS_CUSTOM(new_value)))
				{
					/*
					 * The old external stored value isn't needed
					 * any more after the update
					 */
					ttc->ttc_attr[i].tai_colflags |= TOASTCOL_NEEDS_DELETE_OLD;
					ttc->ttc_flags |= TOAST_NEEDS_DELETE_OLD;
				}
				else if (VARSIZE_EXTERNAL(old_value) == VARSIZE_EXTERNAL(new_value) &&
						 memcmp((char *) old_value, (char *) new_value,
								VARSIZE_EXTERNAL(old_value)) == 0)
				{
					/*
					 * This attribute isn't changed by this update so
					 * we reuse the original reference to the old value
					 * in the new tuple.
					 */
					ttc->ttc_attr[i].tai_colflags |= TOASTCOL_IGNORE;
					continue;
				}
				else if (toaster && toaster->update_toast &&
						 VARATT_IS_CUSTOM(old_value) &&
						 VARATT_IS_CUSTOM(new_value) &&
						 VARATT_CUSTOM_GET_TOASTERID(old_value) == toasterid &&
						 VARATT_CUSTOM_GET_TOASTERID(new_value) == toasterid)
				{
					struct varlena *new_val =
						(struct varlena *) DatumGetPointer(toaster->update_toast(ttc->ttc_rel, toasterid,
											  ttc->ttc_values[i],
											  ttc->ttc_oldvalues[i],
											  false /* speculative */));

					if (new_val)
					{
						if (ttc->ttc_attr[i].tai_colflags & TOASTCOL_NEEDS_FREE)
							pfree(DatumGetPointer(ttc->ttc_values[i]));

						ttc->ttc_values[i] = PointerGetDatum(new_val);
						ttc->ttc_attr[i].tai_colflags |= TOASTCOL_NEEDS_FREE;
						ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);

						new_value = new_val;
					}

					need_detoast = false;
				}
				else
				{
					/*
					 * The old external stored value isn't needed
					 * any more after the update
					 */
					ttc->ttc_attr[i].tai_colflags |= TOASTCOL_NEEDS_DELETE_OLD;
					ttc->ttc_flags |= TOAST_NEEDS_DELETE_OLD;
				}
			}
		}
		else
		{
			/*
			 * For INSERT simply get the new value
			 */
			new_value = (struct varlena *) DatumGetPointer(ttc->ttc_values[i]);

			if (toaster && toaster->copy_toast && !ttc->ttc_isnull[i] &&
				VARATT_IS_CUSTOM(new_value) &&
				VARATT_CUSTOM_GET_TOASTERID(new_value) == toasterid)
			{
				struct varlena *new_val =
					(struct varlena *) DatumGetPointer(toaster->copy_toast(ttc->ttc_rel, toasterid,
										ttc->ttc_values[i],
										false /* speculative */));

				if (new_val)
				{
					if (ttc->ttc_attr[i].tai_colflags & TOASTCOL_NEEDS_FREE)
						pfree(DatumGetPointer(ttc->ttc_values[i]));

					ttc->ttc_values[i] = PointerGetDatum(new_val);
					ttc->ttc_attr[i].tai_colflags |= TOAST_NEEDS_FREE;
					ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);

					new_value = new_val;
				}

				need_detoast = false;
			}
		}

		/*
		 * Handle NULL attributes
		 */
		if (ttc->ttc_isnull[i])
		{
			ttc->ttc_attr[i].tai_colflags |= TOASTCOL_IGNORE;
			ttc->ttc_flags |= TOAST_HAS_NULLS;
			continue;
		}

		/*
		 * Now look at varlena attributes
		 */
		if (att->attlen == -1)
		{
			/*
			 * If the table's attribute says PLAIN always, force it so.
			 */
			if (att->attstorage == TYPSTORAGE_PLAIN)
			{
				ttc->ttc_attr[i].tai_colflags |= TOASTCOL_IGNORE;
				need_detoast = true;
			}

			/*
			 * We took care of UPDATE above, so any external value we find
			 * still in the tuple must be someone else's that we cannot reuse
			 * (this includes the case of an out-of-line in-memory datum).
			 * Fetch it back (without decompression, unless we are forcing
			 * PLAIN storage).  If necessary, we'll push it out as a new
			 * external value below.
			 */
			if (VARATT_IS_EXTERNAL(new_value) && need_detoast)
			{
				ttc->ttc_attr[i].tai_oldexternal = new_value;
				if (att->attstorage == TYPSTORAGE_PLAIN)
					new_value = detoast_attr(new_value);
				else
					new_value = detoast_external_attr(new_value);
				ttc->ttc_values[i] = PointerGetDatum(new_value);
				ttc->ttc_attr[i].tai_colflags |= TOASTCOL_NEEDS_FREE;
				ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);
			}

			/*
			 * Remember the size of this attribute
			 */
			ttc->ttc_attr[i].tai_size = VARSIZE_ANY(new_value);
		}
		else
		{
			/*
			 * Not a varlena attribute, plain storage always
			 */
			ttc->ttc_attr[i].tai_colflags |= TOASTCOL_IGNORE;
			ttc->ttc_attr[i].tai_toaster = NULL;
			ttc->ttc_attr[i].tai_toasterid = InvalidOid;
		}
	}
}

/*
 * Find the largest varlena attribute that satisfies certain criteria.
 *
 * The relevant column must not be marked TOASTCOL_IGNORE, and if the
 * for_compression flag is passed as true, it must also not be marked
 * TOASTCOL_INCOMPRESSIBLE.
 *
 * The column must have attstorage EXTERNAL or EXTENDED if check_main is
 * false, and must have attstorage MAIN if check_main is true.
 *
 * The column must have a minimum size of MAXALIGN(TOAST_POINTER_SIZE);
 * if not, no benefit is to be expected by compressing it.
 *
 * The return value is the index of the biggest suitable column, or
 * -1 if there is none.
 */
int
toast_tuple_find_biggest_attribute(ToastTupleContext *ttc,
								   bool for_compression, bool check_main)
{
	TupleDesc	tupleDesc = ttc->ttc_rel->rd_att;
	int			numAttrs = tupleDesc->natts;
	int			biggest_attno = -1;
	int32		biggest_size = MAXALIGN(TOAST_POINTER_SIZE);
	int32		skip_colflags = TOASTCOL_IGNORE;
	int			i;

	if (for_compression)
		skip_colflags |= TOASTCOL_INCOMPRESSIBLE;

	for (i = 0; i < numAttrs; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupleDesc, i);
		Pointer		value = DatumGetPointer(ttc->ttc_values[i]);

		if ((ttc->ttc_attr[i].tai_colflags & skip_colflags) != 0)
			continue;
		if (VARATT_IS_EXTERNAL(value) && !VARATT_IS_CUSTOM(value))
			continue;			/* can't happen, toast_action would be PLAIN */
		if (for_compression && VARATT_IS_COMPRESSED(value))
			continue;
		if (check_main && att->attstorage != TYPSTORAGE_MAIN)
			continue;
		if (!check_main && att->attstorage != TYPSTORAGE_EXTENDED &&
			att->attstorage != TYPSTORAGE_EXTERNAL)
			continue;

		if (ttc->ttc_attr[i].tai_size > biggest_size)
		{
			biggest_attno = i;
			biggest_size = ttc->ttc_attr[i].tai_size;
		}
	}

	return biggest_attno;
}

/*
 * Try compression for an attribute.
 *
 * If we find that the attribute is not compressible, mark it so.
 */
void
toast_tuple_try_compression(ToastTupleContext *ttc, int attribute)
{
	Datum	   *value = &ttc->ttc_values[attribute];
	Datum		new_value;
	ToastAttrInfo *attr = &ttc->ttc_attr[attribute];

	new_value = toast_compress_datum(*value, attr->tai_compression);

	if (DatumGetPointer(new_value) != NULL)
	{
		/* successful compression */
		if ((attr->tai_colflags & TOASTCOL_NEEDS_FREE) != 0)
			pfree(DatumGetPointer(*value));
		*value = new_value;
		attr->tai_colflags |= TOASTCOL_NEEDS_FREE;
		attr->tai_size = VARSIZE(DatumGetPointer(*value));
		ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);
	}
	else
	{
		/* incompressible, ignore on subsequent compression passes */
		attr->tai_colflags |= TOASTCOL_INCOMPRESSIBLE;
	}
}

/*
 * Move an attribute to external storage.
 */
void
toast_tuple_externalize(ToastTupleContext *ttc, int attribute, int maxDataLen,
						int options)
{
	Datum	   *value = &ttc->ttc_values[attribute];
	Datum		old_value = *value;
	ToastAttrInfo *attr = &ttc->ttc_attr[attribute];

	attr->tai_colflags |= TOASTCOL_IGNORE;
	*value = (Datum)(
				attr->tai_toaster->toast(ttc->ttc_rel,
										 attr->tai_toasterid,
										 old_value,
										 PointerGetDatum(attr->tai_oldexternal),
										 maxDataLen, options)
			);
    if (*value == old_value)
	{
        return;
	}
	if ((attr->tai_colflags & TOASTCOL_NEEDS_FREE) != 0)
		pfree(DatumGetPointer(old_value));
	attr->tai_colflags |= TOASTCOL_NEEDS_FREE;
	ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);
}

static void
toast_delete_external_datum(Datum value, bool is_speculative)
{
	Oid			toasterid;

	if (VARATT_IS_EXTERNAL(value))
		toasterid = DEFAULT_TOASTER_OID;
	else if (VARATT_IS_CUSTOM(value))
		toasterid = VARATT_CUSTOM_GET_TOASTERID(value);
	else
		toasterid = InvalidOid;

	if (toasterid != InvalidOid)
	{
		TsrRoutine *toaster = SearchTsrCache(toasterid);

		toaster->deltoast(value, is_speculative);
	}
}

/*
 * Perform appropriate cleanup after one tuple has been subjected to TOAST.
 */
void
toast_tuple_cleanup(ToastTupleContext *ttc)
{
	TupleDesc	tupleDesc = ttc->ttc_rel->rd_att;
	int			numAttrs = tupleDesc->natts;

	/*
	 * Free allocated temp values
	 */
	if ((ttc->ttc_flags & TOAST_NEEDS_FREE) != 0)
	{
		int			i;

		for (i = 0; i < numAttrs; i++)
		{
			ToastAttrInfo *attr = &ttc->ttc_attr[i];

			if ((attr->tai_colflags & TOASTCOL_NEEDS_FREE) != 0)
				pfree(DatumGetPointer(ttc->ttc_values[i]));
		}
	}

	/*
	 * Delete external values from the old tuple
	 */
	if ((ttc->ttc_flags & TOAST_NEEDS_DELETE_OLD) != 0)
	{
		int			i;

		for (i = 0; i < numAttrs; i++)
		{
			ToastAttrInfo *attr = &ttc->ttc_attr[i];

			if ((attr->tai_colflags & TOASTCOL_NEEDS_DELETE_OLD) != 0)
				toast_delete_external_datum((Datum)(ttc->ttc_oldvalues[i]), false);
		}
	}
}

/*
 * Check for external stored attributes and delete them from the secondary
 * relation.
 */
void
toast_delete_external(Relation rel, Datum *values, bool *isnull,
					  bool is_speculative)
{
	TupleDesc	tupleDesc = rel->rd_att;
	int			numAttrs = tupleDesc->natts;
	int			i;

	for (i = 0; i < numAttrs; i++)
	{
		if (TupleDescAttr(tupleDesc, i)->attlen == -1 && !isnull[i])
			toast_delete_external_datum((Datum)(values[i]),
										is_speculative);
	}
}

/* ----------
 * toast_decompress_datum -
 *
 * Decompress a compressed version of a varlena datum
 */
struct varlena *
toast_decompress_datum(struct varlena *attr)
{
	ToastCompressionId cmid;

	Assert(VARATT_IS_COMPRESSED(attr));

	/*
	 * Fetch the compression method id stored in the compression header and
	 * decompress the data using the appropriate decompression routine.
	 */
	cmid = TOAST_COMPRESS_METHOD(attr);
	switch (cmid)
	{
		case TOAST_PGLZ_COMPRESSION_ID:
			return pglz_decompress_datum(attr);
		case TOAST_LZ4_COMPRESSION_ID:
			return lz4_decompress_datum(attr);
		default:
			elog(ERROR, "invalid compression method id %d", cmid);
			return NULL;		/* keep compiler quiet */
	}
}

/* ----------
 * toast_compress_datum -
 *
 *	Create a compressed version of a varlena datum
 *
 *	If we fail (ie, compressed result is actually bigger than original)
 *	then return NULL.  We must not use compressed data if it'd expand
 *	the tuple!
 *
 *	We use VAR{SIZE,DATA}_ANY so we can handle short varlenas here without
 *	copying them.  But we can't handle external or compressed datums.
 * ----------
 */
Datum
toast_compress_datum(Datum value, char cmethod)
{
	struct varlena *tmp = NULL;
	int32		valsize;
	ToastCompressionId cmid = TOAST_INVALID_COMPRESSION_ID;

	Assert(!VARATT_IS_EXTERNAL(DatumGetPointer(value)));
	Assert(!VARATT_IS_COMPRESSED(DatumGetPointer(value)));

	valsize = VARSIZE_ANY_EXHDR(DatumGetPointer(value));

	/* If the compression method is not valid, use the current default */
	if (!CompressionMethodIsValid(cmethod))
		cmethod = default_toast_compression;

	/*
	 * Call appropriate compression routine for the compression method.
	 */
	switch (cmethod)
	{
		case TOAST_PGLZ_COMPRESSION:
			tmp = pglz_compress_datum((const struct varlena *) value);
			cmid = TOAST_PGLZ_COMPRESSION_ID;
			break;
		case TOAST_LZ4_COMPRESSION:
			tmp = lz4_compress_datum((const struct varlena *) value);
			cmid = TOAST_LZ4_COMPRESSION_ID;
			break;
		default:
			elog(ERROR, "invalid compression method %c", cmethod);
	}

	if (tmp == NULL)
		return PointerGetDatum(NULL);

	/*
	 * We recheck the actual size even if compression reports success, because
	 * it might be satisfied with having saved as little as one byte in the
	 * compressed data --- which could turn into a net loss once you consider
	 * header and alignment padding.  Worst case, the compressed format might
	 * require three padding bytes (plus header, which is included in
	 * VARSIZE(tmp)), whereas the uncompressed format would take only one
	 * header byte and no padding if the value is short enough.  So we insist
	 * on a savings of more than 2 bytes to ensure we have a gain.
	 */
	if (VARSIZE(tmp) < valsize - 2)
	{
		/* successful compression */
		Assert(cmid != TOAST_INVALID_COMPRESSION_ID);
		TOAST_COMPRESS_SET_SIZE_AND_COMPRESS_METHOD(tmp, valsize, cmid);
		return PointerGetDatum(tmp);
	}
	else
	{
		/* incompressible data */
		pfree(tmp);
		return PointerGetDatum(NULL);
	}
}

/* ----------
 * toast_decompress_datum_slice -
 *
 * Decompress the front of a compressed version of a varlena datum.
 * offset handling happens in detoast_attr_slice.
 * Here we just decompress a slice from the front.
 */
struct varlena *
toast_decompress_datum_slice(struct varlena *attr, int32 slicelength)
{
	ToastCompressionId cmid;

	Assert(VARATT_IS_COMPRESSED(attr));

	/*
	 * Some callers may pass a slicelength that's more than the actual
	 * decompressed size.  If so, just decompress normally.  This avoids
	 * possibly allocating a larger-than-necessary result object, and may be
	 * faster and/or more robust as well.  Notably, some versions of liblz4
	 * have been seen to give wrong results if passed an output size that is
	 * more than the data's true decompressed size.
	 */
	if ((uint32) slicelength >= TOAST_COMPRESS_EXTSIZE(attr))
		return toast_decompress_datum(attr);

	/*
	 * Fetch the compression method id stored in the compression header and
	 * decompress the data slice using the appropriate decompression routine.
	 */
	cmid = TOAST_COMPRESS_METHOD(attr);
	switch (cmid)
	{
		case TOAST_PGLZ_COMPRESSION_ID:
			return pglz_decompress_datum_slice(attr, slicelength);
		case TOAST_LZ4_COMPRESSION_ID:
			return lz4_decompress_datum_slice(attr, slicelength);
		default:
			elog(ERROR, "invalid compression method id %d", cmid);
			return NULL;		/* keep compiler quiet */
	}
}

/* ----------
 * detoast_external_attr -
 *
 *	Public entry point to get back a toasted value from
 *	external source (possibly still in compressed format).
 *
 * This will return a datum that contains all the data internally, ie, not
 * relying on external storage or memory, but it can still be compressed or
 * have a short header.  Note some callers assume that if the input is an
 * EXTERNAL datum, the result will be a pfree'able chunk.
 * ----------
 */
struct varlena *
detoast_external_attr(struct varlena *attr)
{
	struct varlena *result;

	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		TsrRoutine *toaster = SearchTsrCache(DEFAULT_TOASTER_OID);
		return (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), 0, -1));
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		/*
		 * This is an indirect pointer --- dereference it
		 */
		struct varatt_indirect redirect;

		VARATT_EXTERNAL_GET_POINTER(redirect, attr);
		attr = (struct varlena *) redirect.pointer;

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(attr));

		/* recurse if value is still external in some other way */
		if (VARATT_IS_EXTERNAL(attr))
			return detoast_external_attr(attr);

		/*
		 * Copy into the caller's memory context, in case caller tries to
		 * pfree the result.
		 */
		result = (struct varlena *) palloc(VARSIZE_ANY(attr));
		memcpy(result, attr, VARSIZE_ANY(attr));
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		/*
		 * This is an expanded-object pointer --- get flat format
		 */
		ExpandedObjectHeader *eoh;
		Size		resultsize;

		eoh = DatumGetEOHP(PointerGetDatum(attr));
		resultsize = EOH_get_flat_size(eoh);
		result = (struct varlena *) palloc(resultsize);
		EOH_flatten_into(eoh, (void *) result, resultsize);
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		Oid	toasterid = VARATT_CUSTOM_GET_TOASTERID(attr);
		TsrRoutine *toaster = SearchTsrCache(toasterid);
		return (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), 0, -1));
	}
	else
	{
		/*
		 * This is a plain value inside of the main tuple - why am I called?
		 */
		result = attr;
	}

	return result;
}


/* ----------
 * detoast_attr -
 *
 *	Public entry point to get back a toasted value from compression
 *	or external storage.  The result is always non-extended varlena form.
 *
 * Note some callers assume that if the input is an EXTERNAL or COMPRESSED
 * datum, the result will be a pfree'able chunk.
 * ----------
 */
struct varlena *
detoast_attr(struct varlena *attr)
{
	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		/*
		 * This is an externally stored datum --- fetch it back from there
		 */
		TsrRoutine *toaster = SearchTsrCache(DEFAULT_TOASTER_OID);
		attr = (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), 0, -1));

		/* If it's compressed, decompress it */
		if (VARATT_IS_COMPRESSED(attr))
		{
			struct varlena *tmp = attr;

			attr = toast_decompress_datum(tmp);
			pfree(tmp);
		}
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		/*
		 * This is an indirect pointer --- dereference it
		 */
		struct varatt_indirect redirect;

		VARATT_EXTERNAL_GET_POINTER(redirect, attr);
		attr = (struct varlena *) redirect.pointer;

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(attr));

		/* recurse in case value is still extended in some other way */
		attr = detoast_attr(attr);

		/* if it isn't, we'd better copy it */
		if (attr == (struct varlena *) redirect.pointer)
		{
			struct varlena *result;

			result = (struct varlena *) palloc(VARSIZE_ANY(attr));
			memcpy(result, attr, VARSIZE_ANY(attr));
			attr = result;
		}
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		/*
		 * This is an expanded-object pointer --- get flat format
		 */
		attr = detoast_external_attr(attr);
		/* flatteners are not allowed to produce compressed/short output */
		Assert(!VARATT_IS_EXTENDED(attr));
	}
	else if (VARATT_IS_COMPRESSED(attr))
	{
		/*
		 * This is a compressed value inside of the main tuple
		 */
		attr = toast_decompress_datum(attr);
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		Oid	toasterid = VARATT_CUSTOM_GET_TOASTERID(attr);
		TsrRoutine *toaster = SearchTsrCache(toasterid);
		attr = (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), 0, -1));
	}
	else if (VARATT_IS_SHORT(attr))
	{
		/*
		 * This is a short-header varlena --- convert to 4-byte header format
		 */
		Size		data_size = VARSIZE_SHORT(attr) - VARHDRSZ_SHORT;
		Size		new_size = data_size + VARHDRSZ;
		struct varlena *new_attr;

		new_attr = (struct varlena *) palloc(new_size);
		SET_VARSIZE(new_attr, new_size);
		memcpy(VARDATA(new_attr), VARDATA_SHORT(attr), data_size);
		attr = new_attr;
	}

	return attr;
}


/* ----------
 * detoast_attr_slice -
 *
 *		Public entry point to get back part of a toasted value
 *		from compression or external storage.
 *
 * sliceoffset is where to start (zero or more)
 * If slicelength < 0, return everything beyond sliceoffset
 * ----------
 */
struct varlena *
detoast_attr_slice(struct varlena *attr,
				   int32 sliceoffset, int32 slicelength)
{
	struct varlena *preslice;
	struct varlena *result;
	char	   *attrdata;
	int32		slicelimit;
	int32		attrsize;

	if (sliceoffset < 0)
		elog(ERROR, "invalid sliceoffset: %d", sliceoffset);

	/*
	 * Compute slicelimit = offset + length, or -1 if we must fetch all of the
	 * value.  In case of integer overflow, we must fetch all.
	 */
	if (slicelength < 0)
		slicelimit = -1;
	else if (pg_add_s32_overflow(sliceoffset, slicelength, &slicelimit))
		slicelength = slicelimit = -1;

	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		struct varatt_external toast_pointer;
		TsrRoutine *toaster = SearchTsrCache(DEFAULT_TOASTER_OID);

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		/* fast path for non-compressed external datums */
		if (!VARATT_EXTERNAL_IS_COMPRESSED(toast_pointer))
		{
			return (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), sliceoffset, slicelength));
		}

		/*
		 * For compressed values, we need to fetch enough slices to decompress
		 * at least the requested part (when a prefix is requested).
		 * Otherwise, just fetch all slices.
		 */
		if (slicelimit >= 0)
		{
			int32		max_size = VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer);

			/*
			 * Determine maximum amount of compressed data needed for a prefix
			 * of a given length (after decompression).
			 *
			 * At least for now, if it's LZ4 data, we'll have to fetch the
			 * whole thing, because there doesn't seem to be an API call to
			 * determine how much compressed data we need to be sure of being
			 * able to decompress the required slice.
			 */
			if (VARATT_EXTERNAL_GET_COMPRESS_METHOD(toast_pointer) ==
				TOAST_PGLZ_COMPRESSION_ID)
				max_size = pglz_maximum_compressed_size(slicelimit, max_size);

			/*
			 * Fetch enough compressed slices (compressed marker will get set
			 * automatically).
			 */

			preslice = (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), 0, max_size));
		}
		else
		{
			VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

			preslice = (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), 0, -1));
		}
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		struct varatt_indirect redirect;

		VARATT_EXTERNAL_GET_POINTER(redirect, attr);

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(redirect.pointer));

		return detoast_attr_slice(redirect.pointer,
								  sliceoffset, slicelength);
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		/* pass it off to detoast_external_attr to flatten */
		preslice = detoast_external_attr(attr);
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		Oid	toasterid = VARATT_CUSTOM_GET_TOASTERID(attr);
		TsrRoutine *toaster = SearchTsrCache(toasterid);
		return (struct varlena *) DatumGetPointer(toaster->detoast(PointerGetDatum(attr), sliceoffset, slicelength));
	}

	else
		preslice = attr;

	Assert(!VARATT_IS_EXTERNAL(preslice));

	if (VARATT_IS_COMPRESSED(preslice))
	{
		struct varlena *tmp = preslice;

		/* Decompress enough to encompass the slice and the offset */
		if (slicelimit >= 0)
			preslice = toast_decompress_datum_slice(tmp, slicelimit);
		else
			preslice = toast_decompress_datum(tmp);

		if (tmp != attr)
			pfree(tmp);
	}

	if (VARATT_IS_SHORT(preslice))
	{
		attrdata = VARDATA_SHORT(preslice);
		attrsize = VARSIZE_SHORT(preslice) - VARHDRSZ_SHORT;
	}
	else
	{
		attrdata = VARDATA(preslice);
		attrsize = VARSIZE(preslice) - VARHDRSZ;
	}

	/* slicing of datum for compressed cases and plain value */

	if (sliceoffset >= attrsize)
	{
		sliceoffset = 0;
		slicelength = 0;
	}
	else if (slicelength < 0 || slicelimit > attrsize)
		slicelength = attrsize - sliceoffset;

	result = (struct varlena *) palloc(slicelength + VARHDRSZ);
	SET_VARSIZE(result, slicelength + VARHDRSZ);

	memcpy(VARDATA(result), attrdata + sliceoffset, slicelength);

	if (preslice != attr)
		pfree(preslice);

	return result;
}

/* ----------
 * toast_raw_datum_size -
 *
 *	Return the raw (detoasted) size of a varlena datum
 *	(including the VARHDRSZ header)
 * ----------
 */
Size
toast_raw_datum_size(Datum value)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	Size		result;

	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		/* va_rawsize is the size of the original datum -- including header */
		struct varatt_external toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);
		result = toast_pointer.va_rawsize;
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		struct varatt_indirect toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(toast_pointer.pointer));

		return toast_raw_datum_size(PointerGetDatum(toast_pointer.pointer));
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		result = EOH_get_flat_size(DatumGetEOHP(value));
	}
	else if (VARATT_IS_COMPRESSED(attr))
	{
		/* here, va_rawsize is just the payload size */
		result = VARDATA_COMPRESSED_GET_EXTSIZE(attr) + VARHDRSZ;
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		/*
		 * Custom toaster raw size of data
		 */
		result = VARATT_CUSTOM_GET_DATA_RAW_SIZE(value);
	}
	else if (VARATT_IS_SHORT(attr))
	{
		/*
		 * we have to normalize the header length to VARHDRSZ or else the
		 * callers of this function will be confused.
		 */
		result = VARSIZE_SHORT(attr) - VARHDRSZ_SHORT + VARHDRSZ;
	}
	else
	{
		/* plain untoasted datum */
		result = VARSIZE(attr);
	}
	return result;
}

/* ----------
 * toast_datum_size
 *
 *	Return the physical storage size (possibly compressed) of a varlena datum
 * ----------
 */
Size
toast_datum_size(Datum value)
{
	struct varlena *attr = (struct varlena *) DatumGetPointer(value);
	Size		result;

	if (VARATT_IS_EXTERNAL_ONDISK(attr))
	{
		/*
		 * Attribute is stored externally - return the extsize whether
		 * compressed or not.  We do not count the size of the toast pointer
		 * ... should we?
		 */
		struct varatt_external toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);
		result = VARATT_EXTERNAL_GET_EXTSIZE(toast_pointer);
	}
	else if (VARATT_IS_EXTERNAL_INDIRECT(attr))
	{
		struct varatt_indirect toast_pointer;

		VARATT_EXTERNAL_GET_POINTER(toast_pointer, attr);

		/* nested indirect Datums aren't allowed */
		Assert(!VARATT_IS_EXTERNAL_INDIRECT(attr));

		return toast_datum_size(PointerGetDatum(toast_pointer.pointer));
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(attr))
	{
		result = EOH_get_flat_size(DatumGetEOHP(value));
	}
	else if (VARATT_IS_CUSTOM(attr))
	{
		result = VARATT_CUSTOM_GET_DATA_SIZE(attr);
	}
	else if (VARATT_IS_SHORT(attr))
	{
		result = VARSIZE_SHORT(attr);
	}
	else
	{
		/*
		 * Attribute is stored inline either compressed or not, just calculate
		 * the size of the datum in either case.
		 */
		result = VARSIZE(attr);
	}
	return result;
}

void
fetch_toast_slice(Relation toastrel, Oid valueid,
					   struct varlena *attr, int32 attrsize,
					   int32 sliceoffset, int32 slicelength,
					   struct varlena *result)
{
	toast_fetch_toast_slice( toastrel, valueid,
					   attr, attrsize,
					   sliceoffset, slicelength,
					   result);
}
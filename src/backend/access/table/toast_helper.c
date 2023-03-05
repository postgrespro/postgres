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

#include "access/detoast.h"
#include "access/table.h"
#include "access/toast_helper.h"
#include "access/toast_internals.h"
#include "catalog/pg_type_d.h"
#include "varatt.h"
#include "access/toast_hook.h"

Toastapi_toast_hook_type Toastapi_toast_hook = NULL;
Toastapi_update_hook_type Toastapi_update_hook = NULL;
Toastapi_copy_hook_type Toastapi_copy_hook = NULL;
Toastapi_delete_hook_type Toastapi_delete_hook = NULL;
Toastapi_size_hook_type Toastapi_size_hook = NULL;

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
		bool	need_detoast = true;

		ttc->ttc_attr[i].tai_colflags = 0;
		ttc->ttc_attr[i].tai_oldexternal = NULL;
		ttc->ttc_attr[i].tai_compression = att->attcompression;
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
					 * The old external stored value isn't needed any more
					 * after the update
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
				else if (Toastapi_update_hook &&
						 ((VARATT_IS_CUSTOM(old_value) && VARATT_IS_CUSTOM(new_value))
						 || (VARATT_IS_EXTERNAL(old_value) && VARATT_IS_EXTERNAL(new_value))))
				{
					struct varlena *new_val;
					new_val =
						(struct varlena *) DatumGetPointer(Toastapi_update_hook(ttc->ttc_rel, i,
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
			if(att->attstorage == TYPSTORAGE_EXTERNAL)
			{
				if (Toastapi_copy_hook && !ttc->ttc_isnull[i] &&
					VARATT_IS_EXTERNAL(new_value))
				{
					struct varlena *new_val =
						(struct varlena *) DatumGetPointer(Toastapi_copy_hook(ttc->ttc_rel,
										ttc->ttc_values[i],
										false,
										i));
					if (new_val)
					{
						if (ttc->ttc_attr[i].tai_colflags & TOASTCOL_NEEDS_FREE)
							pfree(DatumGetPointer(ttc->ttc_values[i]));

						ttc->ttc_values[i] = PointerGetDatum(new_val);
						ttc->ttc_attr[i].tai_colflags |= TOAST_NEEDS_FREE;
						ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);

						new_value = new_val;
					}
				}
			}
			need_detoast = false;
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
			if(VARATT_IS_EXTERNAL(new_value) && need_detoast)
			/* (att->attstorage == TYPSTORAGE_EXTERNAL || att->attstorage == TYPSTORAGE_EXTENDED
				|| att->attstorage == TYPSTORAGE_PLAIN ) */
			{
/*
				if(VARATT_IS_EXTERNAL(new_value) && need_detoast)
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
*/
				ttc->ttc_attr[i].tai_oldexternal = new_value;
				if (att->attstorage == TYPSTORAGE_PLAIN)
				{
					new_value = detoast_attr(new_value);
				}
				else
				{
					new_value = detoast_external_attr(new_value);
					ttc->ttc_values[i] = PointerGetDatum(new_value);
					ttc->ttc_attr[i].tai_colflags |= TOASTCOL_NEEDS_FREE;
					ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);
				}
			}
			/*
			 * Remember the size of this attribute
			 */
				//if(VARATT_IS_EXTERNAL(new_value)) 
/*
				if(VARATT_IS_EXTERNAL(new_value))
					if(VARATT_IS_CUSTOM(new_value) && Toastapi_size_hook)
						ttc->ttc_attr[i].tai_size = Toastapi_size_hook(VARTAG_EXTERNAL(new_value), new_value);
					else
						ttc->ttc_attr[i].tai_size = VARSIZE_ANY(new_value);
				else*/
					ttc->ttc_attr[i].tai_size = VARSIZE_ANY(new_value);
		}
		else
		{
			/*
			 * Not a varlena attribute, plain storage always
			 */
			ttc->ttc_attr[i].tai_colflags |= TOASTCOL_IGNORE;
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

		if ((ttc->ttc_attr[i].tai_colflags & skip_colflags) != 0)
			continue;
		if (VARATT_IS_EXTERNAL(DatumGetPointer(ttc->ttc_values[i])))
			continue;			/* can't happen, toast_action would be PLAIN */
		if (for_compression &&
			VARATT_IS_COMPRESSED(DatumGetPointer(ttc->ttc_values[i])))
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
toast_tuple_externalize(ToastTupleContext *ttc, int attribute, int options)
{
	Datum	   *value = &ttc->ttc_values[attribute];
	Datum		old_value = *value;
	ToastAttrInfo *attr = &ttc->ttc_attr[attribute];

	attr->tai_colflags |= TOASTCOL_IGNORE;

	if(Toastapi_toast_hook)
	{
		*value = Toastapi_toast_hook(ttc, attribute, 0, options);
	}
	else
	{
		*value = toast_save_datum(ttc->ttc_rel, old_value, attr->tai_oldexternal,
			options);
	}
	if ((attr->tai_colflags & TOASTCOL_NEEDS_FREE) != 0)
		pfree(DatumGetPointer(old_value));
	attr->tai_colflags |= TOASTCOL_NEEDS_FREE;
	ttc->ttc_flags |= (TOAST_NEEDS_CHANGE | TOAST_NEEDS_FREE);
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
			{
				if(Toastapi_delete_hook) Toastapi_delete_hook(ttc->ttc_rel, ttc->ttc_oldvalues[i], false, i);
				else
					toast_delete_datum(ttc->ttc_rel, ttc->ttc_oldvalues[i], false);
			}
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
		if (TupleDescAttr(tupleDesc, i)->attlen == -1)
		{
			Datum		value = values[i];

			if (isnull[i])
				continue;
			if(Toastapi_delete_hook) Toastapi_delete_hook(rel, value, is_speculative, i);
			else if (VARATT_IS_EXTERNAL_ONDISK(value))
				toast_delete_datum(rel, value, is_speculative);
		}
	}
}

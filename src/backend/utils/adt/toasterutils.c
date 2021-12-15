/*-------------------------------------------------------------------------
 *
 * amutils.c
 *	  SQL-level APIs related to index access methods.
 *
 * Copyright (c) 2016-2021, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/amutils.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/toasterapi.h"
#include "access/htup_details.h"
#include "catalog/pg_class.h"
#include "catalog/pg_index.h"
#include "utils/builtins.h"
#include "utils/syscache.h"


/* Convert string property name to enum, for efficiency */
struct tsr_propname
{
	const char *name;
	IndexTsrProperty prop;
};

static const struct tsr_propname tsr_propnames[] =
{
	{
		"version", TSRPROP_VERSION
	},
	{
		"compressed", TSRPROP_COMPRESSED
	},
	{
		"nulls_first", TSRPROP_RESERVED
	},
};

static IndexTsrProperty
lookup_prop_name(const char *name)
{
	int			i;

	for (i = 0; i < lengthof(tsr_propnames); i++)
	{
		if (pg_strcasecmp(tsr_propnames[i].name, name) == 0)
			return tsr_propnames[i].prop;
	}

	/* We do not throw an error, so that Toasters can define their own properties */
	return TSRPROP_UNKNOWN;
}

/*
 * Common code for properties that are just bit tests of indoptions.
 *
 * tuple: the pg_index heaptuple
 * attno: identify the index column to test the indoptions of.
 * guard: if false, a boolean false result is forced (saves code in caller).
 * iopt_mask: mask for interesting indoption bit.
 * iopt_expect: value for a "true" result (should be 0 or iopt_mask).
 *
 * Returns false to indicate a NULL result (for "unknown/inapplicable"),
 * otherwise sets *res to the boolean value to return.
 */
static bool
test_indoption(HeapTuple tuple, int attno, bool guard,
			   int16 iopt_mask, int16 iopt_expect,
			   bool *res)
{
	Datum		datum;
	bool		isnull;
	int2vector *indoption;
	int16		indoption_val;

	if (!guard)
	{
		*res = false;
		return true;
	}

	datum = SysCacheGetAttr(INDEXRELID, tuple,
							Anum_pg_index_indoption, &isnull);
	Assert(!isnull);

	indoption = ((int2vector *) DatumGetPointer(datum));
	indoption_val = indoption->values[attno - 1];

	*res = (indoption_val & iopt_mask) == iopt_expect;

	return true;
}


/*
 * Test property of a Toaster.
 *
 * This is common code for different SQL-level funcs, so the amoid and
 * index_oid parameters are mutually exclusive; we look up the toasteroid from the
 * index_oid if needed, or if no index oid is given, we're looking at Toster-wide
 * properties.
 */
static Datum
toaster_property(FunctionCallInfo fcinfo,
				 const char *propname,
				 Oid tsroid, Oid index_oid, int attno)
{
	bool		res = false;
	bool		isnull = false;
	int			natts = 0;
	IndexTsrProperty prop;
	IndexTsrRoutine *routine;

	/* Try to convert property name to enum (no error if not known) */
	prop = lookup_prop_name(propname);

	/* If we have an index OID, look up the AM, and get # of columns too */
	if (OidIsValid(index_oid))
	{
		HeapTuple	tuple;
		Form_pg_class rd_rel;

		Assert(!OidIsValid(tsroid));
		tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(index_oid));
		if (!HeapTupleIsValid(tuple))
			PG_RETURN_NULL();
		rd_rel = (Form_pg_class) GETSTRUCT(tuple);
		if (rd_rel->relkind != RELKIND_INDEX &&
			rd_rel->relkind != RELKIND_PARTITIONED_INDEX)
		{
			ReleaseSysCache(tuple);
			PG_RETURN_NULL();
		}
		tsroid = rd_rel->relam;
		natts = rd_rel->relnatts;
		ReleaseSysCache(tuple);
	}

	/*
	 * At this point, either index_oid == InvalidOid or it's a valid index
	 * OID. Also, after this test and the one below, either attno == 0 for
	 * index-wide or AM-wide tests, or it's a valid column number in a valid
	 * index.
	 */
	if (attno < 0 || attno > natts)
		PG_RETURN_NULL();

	/*
	 * Get AM information.  If we don't have a valid AM OID, return NULL.
	 */
	routine = GetIndexTsrRoutineByTsrId(tsroid, true);
	if (routine == NULL)
		PG_RETURN_NULL();

	/*
	 * If there's an AM property routine, give it a chance to override the
	 * generic logic.  Proceed if it returns false.
	 */
	if (routine->tsrproperty &&
		routine->tsrproperty(index_oid, attno, prop, propname,
							&res, &isnull))
	{
		if (isnull)
			PG_RETURN_NULL();
		PG_RETURN_BOOL(res);
	}

	if (attno > 0)
	{
		HeapTuple	tuple;
		Form_pg_index rd_index;
		bool		iskey = true;

		/*
		 * Handle column-level properties. Many of these need the pg_index row
		 * (which we also need to use to check for nonkey atts) so we fetch
		 * that first.
		 */
		tuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(index_oid));
		if (!HeapTupleIsValid(tuple))
			PG_RETURN_NULL();
		rd_index = (Form_pg_index) GETSTRUCT(tuple);

		Assert(index_oid == rd_index->indexrelid);
		Assert(attno > 0 && attno <= rd_index->indnatts);

		isnull = true;

		/*
		 * If amcaninclude, we might be looking at an attno for a nonkey
		 * column, for which we (generically) assume that most properties are
		 * null.
		 */
		if (routine->amcaninclude
			&& attno > rd_index->indnkeyatts)
			iskey = false;

		switch (prop)
		{
			case TSRPROP_VERSION:
				if (iskey)
				{
					res = routine->toasterversion;
					isnull = false;
				}
				break;

			case TSRPROP_COMPRESSED:
				if (iskey)
				{
					res = routine->toastercompressed;
					isnull = false;
				}
				break;

			case TSRPROP_RESERVED:
				if (iskey)
				{
					res = routine->toasterreserved;
					isnull = false;
				}
				break;

			default:
				break;
		}

		ReleaseSysCache(tuple);

		if (!isnull)
			PG_RETURN_BOOL(res);
		PG_RETURN_NULL();
	}

	if (OidIsValid(index_oid))
	{
		/*
		 * Handle index-level properties.  Currently, these only depend on the
		 * AM, but that might not be true forever, so we make users name an
		 * index not just an AM.
		 */
		switch (prop)
		{
			case TSRPROP_COMPRESSED:
				PG_RETURN_BOOL(routine->toastercompressed);

			default:
				PG_RETURN_NULL();
		}
	}

}

/*
 * Test property of an AM specified by Toaster OID
 */
Datum
pg_toaster_has_property(PG_FUNCTION_ARGS)
{
	Oid			tsroid = PG_GETARG_OID(0);
	char	   *propname = text_to_cstring(PG_GETARG_TEXT_PP(1));

	return toaster_property(fcinfo, propname, tsroid, InvalidOid, 0);
}

#include "postgres.h"

#include "access/htup_details.h"
#include "access/reloptions.h"
#include "access/table.h"
#include "access/transam.h"
#include "catalog/indexing.h"
#include "commands/defrem.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/regproc.h"
#include "utils/rel.h"
#include "utils/syscache.h"

#include "toastapi.h"
#include "toastapi_internals.h"
#include "toastapi_sqlfuncs.h"
#include "pg_toaster.h"

PG_FUNCTION_INFO_V1(add_toaster);

Datum
add_toaster(PG_FUNCTION_ARGS)
{
	Relation	rel;
	Oid			tsroid;
	Oid			ex_tsroid = InvalidOid;
	char	   *tsrname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *tsrhandler = text_to_cstring(PG_GETARG_TEXT_PP(1));
	List	   *namelist;

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create toaster \"%s\"",
						tsrname),
				 errhint("Must be superuser to create a toaster.")));

	namelist = stringToQualifiedNameList(tsrhandler, NULL);

	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */
	tsroid = lookup_toaster_handler_func(namelist);

	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	ex_tsroid = get_toaster_by_name(rel, tsrname, NULL);

	if (!OidIsValid(ex_tsroid))
	{
		/*
		 * Insert tuple into pg_toaster.
		 */
		Datum		values[Natts_pg_toaster];
		bool		nulls[Natts_pg_toaster];
		NameData	tsrnmdata;
		HeapTuple	tup;
		/* TsrRoutine *tsr = GetTsrRoutine(tsroid); */

		memset(values, 0, sizeof(values));
		memset(nulls, false, sizeof(nulls));

		namestrcpy(&tsrnmdata, tsrname);

		ex_tsroid = GetNewObjectId();

		values[Anum_pg_toaster_oid - 1] = ObjectIdGetDatum(ex_tsroid);
		values[Anum_pg_toaster_tsrname - 1] = NameGetDatum(&tsrnmdata);
		values[Anum_pg_toaster_tsrhandler - 1] = ObjectIdGetDatum(tsroid);

		tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);

		CatalogTupleInsert(rel, tup);
		heap_freetuple(tup);
	}

	table_close(rel, RowExclusiveLock);

	PG_RETURN_OID(ex_tsroid);
}

PG_FUNCTION_INFO_V1(set_toaster);

Datum
set_toaster(PG_FUNCTION_ARGS)
{
	ToastAttrContext cxt;
	Relation	rel;
	Relation	tsrrel;
	char	   *tsrname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	text	   *relname = PG_GETARG_TEXT_PP(1);
	char	   *attname = text_to_cstring(PG_GETARG_TEXT_PP(2));
	Oid			tsroid;
	Oid			tsrhandler;
	char		str[12];
	char		nstr[12];
	int			len = 0;
	int			attnum pg_attribute_unused();

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create toaster \"%s\"",
						tsrname),
				 errhint("Must be superuser to create a toaster.")));

	/* Get relation oid by name */
	rel = get_rel_from_relname(relname, AccessShareLock, ACL_SELECT);

	/* Get toaster id by name */
	tsrrel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);
	tsroid = get_toaster_by_name(tsrrel, tsrname, &tsrhandler);
	table_close(tsrrel, AccessShareLock);

	if (!OidIsValid(tsroid))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("cannot find toaster with name \"%s\"", tsrname)));

	Assert(OidIsValid(tsrhandler));

	/* Find attribute and check whether toaster is applicable to it */
	toaster_attopts_init(&cxt, rel, attname, true, tsroid);

	/* Check toaster handler and routine */
	(void) SearchTsrHandlerCache(tsrhandler); // GetTsrRoutine(tsrhandler);

	/* Set toaster variables - oid, toast relation id, handler for fast access */
	len = pg_ltoa(tsrhandler, str);
	if (len <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid handler OID \"%u\"",
						tsrhandler)));

	len = pg_ltoa(tsroid, nstr);
	if (len <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid toaster OID \"%u\"",
						tsroid)));

	toaster_attopts_set(&cxt, ATT_HANDLER_NAME, str, -1);
	toaster_attopts_set(&cxt, ATT_TOASTER_NAME, nstr, -1);
	toaster_attopts_update(&cxt);
	toaster_attopts_free(&cxt);

	table_close(rel, AccessShareLock);

	PG_RETURN_OID(tsroid);
}

PG_FUNCTION_INFO_V1(reset_toaster);

Datum
reset_toaster(PG_FUNCTION_ARGS)
{
	text	   *relname = PG_GETARG_TEXT_PP(0);
	char	   *attname = text_to_cstring(PG_GETARG_TEXT_PP(1));
	ToastAttrContext cxt;
	Relation	rel;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to reset toaster for table \"%s\"",
						text_to_cstring(relname)),
				 errhint("Must be superuser to reset a toaster.")));

	rel = get_rel_from_relname(relname, AccessShareLock, ACL_SELECT);

	toaster_attopts_init(&cxt, rel, attname, true, InvalidOid);
	toaster_attopts_clear(&cxt, ATT_TOASTER_NAME);
	toaster_attopts_clear(&cxt, ATT_HANDLER_NAME);
	toaster_attopts_update(&cxt);
	toaster_attopts_free(&cxt);

	table_close(rel, AccessShareLock);

	PG_RETURN_OID(InvalidOid);
}

PG_FUNCTION_INFO_V1(get_toaster);

Datum get_toaster(PG_FUNCTION_ARGS)
{
	text	   *relname = PG_GETARG_TEXT_PP(0);
	char	   *attname = text_to_cstring(PG_GETARG_TEXT_PP(1));
	Relation	rel;
	ToastAttrContext cxt;
	const char *tsroid_str;
	Oid			tsroid;
	char	   *tsrname;

	rel = get_rel_from_relname(relname, AccessShareLock, ACL_SELECT);

	toaster_attopts_init(&cxt, rel, attname, false, InvalidOid);
	tsroid_str = toaster_attopts_get(&cxt, ATT_TOASTER_NAME);
	toaster_attopts_free(&cxt);

	table_close(rel, AccessShareLock);

	if (!tsroid_str)
		PG_RETURN_NULL();

	tsroid = atoi(tsroid_str);
	tsrname = get_toaster_name(tsroid);

	elog(NOTICE,"%s", tsrname);
	//PG_RETURN_TEXT_P(cstring_to_text(tsrname));
	PG_RETURN_OID(tsroid);
}

PG_FUNCTION_INFO_V1(drop_toaster);

Datum
drop_toaster(PG_FUNCTION_ARGS)
{
	char	   *tsrname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	Relation	attrelation;
	Relation	rel;
	Datum		o_datum;
	int			l_idx = 0;
	Oid			tsroid = InvalidOid;
	bool		found = false;
	SysScanDesc scan;
	HeapTuple	tup = NULL;
	HeapTuple	tsrtup;
	char		s_tsrid[12];
	int			len = 0;

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to drop toaster \"%s\"",
						tsrname),
				 errhint("Must be superuser to drop a toaster.")));

	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);
	tsroid = get_toaster_by_name(rel, tsrname, NULL);
	table_close(rel, RowExclusiveLock);

	if (!OidIsValid(tsroid))
		PG_RETURN_NULL();

	len = pg_ltoa(tsroid, s_tsrid);
	found = false;

	if(len != 0)
	{
		attrelation = table_open(AttributeRelationId, RowExclusiveLock);
		scan = systable_beginscan(attrelation, InvalidOid, false,
								  NULL, 0, NULL);

		while (HeapTupleIsValid(tup = systable_getnext(scan)))
		{
			bool		isnull;
			ListCell   *cell;
			List	   *o_list;

			o_datum = SysCacheGetAttr(ATTNAME, tup, Anum_pg_attribute_attoptions,
								&isnull);
			o_list = untransformRelOptions(o_datum);

			foreach(cell, o_list)
			{
				DefElem    *def = (DefElem *) lfirst(cell);
				char	   *str;

				l_idx++;
				str = defGetString(def);

				if (!strcmp(def->defname, ATT_TOASTER_NAME) &&
					str && !strcmp(s_tsrid, str))
				{
					found = true;
					break;
				}
			}
		}
		systable_endscan(scan);
		table_close(attrelation, RowExclusiveLock);
	}

	if (found)
		tsroid = InvalidOid;
	else
	{
		rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

		scan = systable_beginscan(rel, InvalidOid, false,
							  NULL, 0, NULL);
		tsroid = InvalidOid;
		while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
		{
			if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
			{
				tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
				break;
			}
		}

		if (OidIsValid(tsroid))
			CatalogTupleDelete(rel, &tsrtup->t_self);

		systable_endscan(scan);
		table_close(rel, RowExclusiveLock);
	}

	if (OidIsValid(tsroid))
		PG_RETURN_OID(tsroid);
	else
		PG_RETURN_NULL();
}

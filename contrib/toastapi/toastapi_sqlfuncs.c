#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "toastapi.h"
#include "access/toast_helper.h"

#include "access/htup_details.h"
#include "commands/defrem.h"
#include "lib/pairingheap.h"
#include "utils/builtins.h"
#include "utils/memutils.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/heaptoast.h"
#include "access/reloptions.h"
#include "access/attoptions.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "miscadmin.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "catalog/pg_namespace.h"
#include "utils/guc.h"

#include "catalog/binary_upgrade.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_class.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "nodes/makefuncs.h"
#include "storage/lock.h"

#include "catalog/pg_am_d.h"
#include "commands/vacuum.h"
#include "funcapi.h"
#include "storage/bufmgr.h"

#include "libpq/auth.h"
#include "utils/guc.h"
#include "utils/timestamp.h"

#include "utils/lsyscache.h"
#include "utils/regproc.h"

#include "access/toast_internals.h"
#include "access/toast_hook.h"
#include "utils/elog.h"
#include "pg_toaster.h"
#include "pg_toastrel.h"
#include "utils/varlena.h"
#include "varatt_custom.h"
#include "toastapi_internals.h"
#include "toastapi_sqlfuncs.h"

static Oid
find_toaster_by_name(Relation pg_toaster_rel, const char *tsrname, Oid *tsrhandler)
{
	SysScanDesc scan;
	HeapTuple	tup;
	Oid			tsroid = InvalidOid;

	scan = systable_beginscan(pg_toaster_rel, InvalidOid, false, NULL, 0, NULL);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_toaster tsr = (Form_pg_toaster) GETSTRUCT(tup);

		if (!namestrcmp(&tsr->tsrname, tsrname))
		{
			tsroid = tsr->oid;

			if (tsrhandler)
				*tsrhandler = tsr->tsrhandler;

			break;
		}
	}

	systable_endscan(scan);

	return tsroid;
}


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

	ex_tsroid = find_toaster_by_name(rel, tsrname, NULL);

	if (!OidIsValid(ex_tsroid))
	{
		/*
		 * Insert tuple into pg_toaster.
		 */
		Datum		values[Natts_pg_toaster];
		bool		nulls[Natts_pg_toaster];
		NameData	tsrnmdata;
		HeapTuple	tup;

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
	Relation	rel;
	Relation	tsrrel;
	Relation	attrelation;
	char	   *tsrname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *relname = text_to_cstring(PG_GETARG_TEXT_PP(1));
	char	   *attname = text_to_cstring(PG_GETARG_TEXT_PP(2));
	Oid			relid = InvalidOid;
	Oid			tsroid = InvalidOid;
	Oid			tsrhandler = InvalidOid;
	Datum		d = (Datum) 0;
	HeapTuple	tuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	char		str[12];
	char		nstr[12];
	ToastAttributes tattrs;
	int			len = 0;

	if (strlen(tsrname) == 0)
		PG_RETURN_NULL();
	if (strlen(relname) == 0)
		PG_RETURN_NULL();
	if (strlen(attname) == 0)
		PG_RETURN_NULL();

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create toaster \"%s\"",
						tsrname),
				 errhint("Must be superuser to create a toaster.")));

	rel = get_rel_from_relname(cstring_to_text(relname), AccessShareLock, ACL_SELECT);
	relid = RelationGetRelid(rel);
	table_close(rel, AccessShareLock);

	tsrrel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);
	tsroid = find_toaster_by_name(tsrrel, tsrname, &tsrhandler);
	table_close(tsrrel, AccessShareLock);

	if (!OidIsValid(tsroid))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("cannot find toaster with name \"%s\"", tsrname)));

	Assert(OidIsValid(tsrhandler));

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(rel))));
	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));

	ReleaseSysCache(tuple);

	tattrs = palloc(sizeof(ToastAttributesData));
	tattrs->attnum = -1;
	tattrs->ntoasters = 0;
	tattrs->toaster = NULL;
	tattrs->toasteroid = InvalidOid;
	tattrs->toasthandleroid = InvalidOid;
	tattrs->toastreloid = rel->rd_rel->reltoastrelid;

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_HANDLER_NAME);

	if (d != (Datum) 0)
		tattrs->toasthandleroid = atoi(DatumGetCString(d));

	if (!OidIsValid(tattrs->toastreloid))
	{
		TsrRoutine *tsr;
		tsr = GetTsrRoutine(tsrhandler);
		rel = get_rel_from_relname(cstring_to_text(relname), RowExclusiveLock, ACL_INSERT);
		relid = RelationGetRelid(rel);
		tattrs->toaster = tsr;

		d = tsr->init(rel,
					  tsroid,
					  (Datum) 0,
					  attnum,
					  RowExclusiveLock,
					  false,
					  InvalidOid,
					  tattrs);
		tattrs->toastreloid = DatumGetObjectId(d);
		table_close(rel, RowExclusiveLock);
	}

	pfree(tattrs);
	table_close(attrelation, RowExclusiveLock);

	/* Set toaster variables - oid, toast relation id, handler for fast access */
	len = pg_ltoa(tsrhandler, str);
	if (len <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Invalid handler OID \"%u\"",
						tsrhandler)));

	d = attopts_set_toaster_opts(relid, attname, ATT_HANDLER_NAME, str, -1);

	len = pg_ltoa(tsroid, nstr);
	if (len <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("Invalid Toaster OID \"%u\"",
						tsroid)));

	d = attopts_set_toaster_opts(relid, attname, ATT_TOASTER_NAME, nstr, -1);

	PG_RETURN_OID(tsroid);
}

PG_FUNCTION_INFO_V1(reset_toaster);

Datum
reset_toaster(PG_FUNCTION_ARGS)
{
	Relation	rel;
	Relation	attrelation;
	char	   *relname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *attname = text_to_cstring(PG_GETARG_TEXT_PP(1));
	Oid			relid = InvalidOid;
	HeapTuple	tuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;

	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to reset toaster for table \"%s\"",
						relname),
				 errhint("Must be superuser to reset a toaster.")));

	rel = get_rel_from_relname(cstring_to_text(relname), AccessShareLock, ACL_SELECT);
	relid = RelationGetRelid(rel);
	table_close(rel, AccessShareLock);

	attrelation = table_open(AttributeRelationId, AccessShareLock);
	tuple = SearchSysCacheAttName(relid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(rel))));
	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));

	ReleaseSysCache(tuple);
	table_close(attrelation, AccessShareLock);

	attopts_clear_toaster_opts(relid, attname, ATT_TOASTER_NAME);
	attopts_clear_toaster_opts(relid, attname, ATT_HANDLER_NAME);

	PG_RETURN_OID(InvalidOid);
}

PG_FUNCTION_INFO_V1(get_toaster);

Datum get_toaster(PG_FUNCTION_ARGS)
{
	Relation	rel;
	Relation	tsrrel;
	char	   *relname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *attname = text_to_cstring(PG_GETARG_TEXT_PP(1));
   Oid relid = InvalidOid;
	SysScanDesc scan;
	uint32 total_entries = 0;
	Datum d = (Datum) 0;
	Relation attrelation;
   Oid tsroid = InvalidOid;
	HeapTuple	tuple,
				tsrtup;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	char *tsrname = "";

	if(strlen(relname) == 0)
		PG_RETURN_NULL();
	if(strlen(attname) == 0)
		PG_RETURN_NULL();

	rel = get_rel_from_relname(cstring_to_text(relname), AccessShareLock, ACL_SELECT);
	relid = RelationGetRelid(rel);
	table_close(rel, AccessShareLock);

	attrelation = table_open(AttributeRelationId, AccessShareLock);
	tuple = SearchSysCacheAttName(relid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(rel))));
	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	ReleaseSysCache(tuple);
	table_close(attrelation, AccessShareLock);

	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));

	d = attopts_get_toaster_opts(relid, attname, attnum, ATT_TOASTER_NAME);
	if(d != (Datum) 0)
		tsroid = atoi(DatumGetCString(d));

	tsrrel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), AccessShareLock, ACL_SELECT);

	scan = systable_beginscan(tsrrel, InvalidOid, false,
							  NULL, 0, NULL);

	while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
	{
		total_entries++;
		if((((Form_pg_toaster) GETSTRUCT(tsrtup))->oid) == tsroid)
		{
			tsrname = (NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname));
			break;
		}
	}

	systable_endscan(scan);
	table_close(tsrrel, AccessShareLock);
	elog(NOTICE,"%s", tsrname);
	// res = PointerGetDatum(cstring_to_text_with_len(tsrname, strlen(tsrname)));

	PG_RETURN_OID(tsroid);
}

PG_FUNCTION_INFO_V1(drop_toaster);

Datum
drop_toaster(PG_FUNCTION_ARGS)
{
	char	   *tsrname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	Relation	attrelation;
	Relation	rel;
	Datum o_datum;
	int l_idx = 0;
	Oid			tsroid = InvalidOid;
	bool		found = false;
	SysScanDesc scan;
	HeapTuple	tup = NULL;
	HeapTuple	tsrtup;
	uint32      total_entries = 0;
	char s_tsrid[12];
	int len = 0;

	if(tsrname == NULL || strlen(tsrname) == 0)
		PG_RETURN_NULL();

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to drop toaster \"%s\"",
						tsrname),
				 errhint("Must be superuser to drop a toaster.")));

	rel = get_rel_from_relname(cstring_to_text(PG_TOASTER_NAME), RowExclusiveLock, ACL_INSERT);

	scan = systable_beginscan(rel, InvalidOid, false,
							  NULL, 0, NULL);

	while (HeapTupleIsValid(tsrtup = systable_getnext(scan)))
	{
		total_entries++;
		if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
		{
			tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
			break;
		}
	}

	systable_endscan(scan);
	table_close(rel, RowExclusiveLock);

	if (!OidIsValid(tsroid))
		PG_RETURN_OID(InvalidOid);

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

				char *str;
				l_idx++;
				str = defGetString(def);

				if(str && strcmp(s_tsrid, str) == 0)
				{
					found = true;
					break;
				}
			}
			total_entries++;
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
			total_entries++;
			if(strcmp(NameStr(((Form_pg_toaster) GETSTRUCT(tsrtup))->tsrname), tsrname) == 0)
			{
				tsroid = ((Form_pg_toaster) GETSTRUCT(tsrtup))->oid;
				break;
			}
		}

		if( OidIsValid(tsroid))
			CatalogTupleDelete(rel, &tsrtup->t_self);

		systable_endscan(scan);
		table_close(rel, RowExclusiveLock);
	}

	PG_RETURN_OID(tsroid);
}
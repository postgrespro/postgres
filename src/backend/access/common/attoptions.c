/*-------------------------------------------------------------------------
 *
 * attoptions.c
 *	  Retrieve compressed or external variable size attributes.
 *
 * Copyright (c) 2000-2023, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/backend/access/common/attoptions.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "varatt.h"
#include "fmgr.h"
#include "access/heaptoast.h"
#include "access/htup_details.h"
#include "commands/defrem.h"
#include "utils/builtins.h"
#include "utils/syscache.h"
#include "access/toast_compression.h"
#include "access/xact.h"
#include "catalog/binary_upgrade.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/heap.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/pg_am.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "catalog/toasting.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "access/relation.h"
#include "access/genam.h"
#include "access/table.h"
#include "access/reloptions.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "access/attoptions.h"
#include "utils/lsyscache.h"
#include "utils/varlena.h"
#include "utils/guc.h"
#include "parser/parse_func.h"

Datum
relopts_get_toaster_opts(Datum reloptions, Oid *relid, Oid *toasterid)
{
	List	   *options_list = untransformRelOptions(reloptions);
	ListCell   *cell;

	foreach(cell, options_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);

		if (strcmp(def->defname, "toastrelid") == 0
			|| strcmp(def->defname, "toasteroid") == 0
			|| strcmp(def->defname, "toasthandler") == 0)
		{
			char	   *value;
			int			int_val;
			bool		is_parsed;

			value = defGetString(def);
			is_parsed = parse_int(value, &int_val, 0, NULL);

			if (!is_parsed)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("invalid value for integer option \"%s\": %s",
								def->defname, value)));

			if (int_val <= 0)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("\"%s\" must be an integer value greater than zero",
								def->defname)));
			if(strcmp(def->defname, "toastrelid") == 0)
				*relid = int_val;
			if(strcmp(def->defname, "toasteroid") == 0)
				*toasterid = int_val;
		}
	}
	return ObjectIdGetDatum(*relid);
}

Datum
relopts_set_toaster_opts(Datum reloptions, Oid relid, Oid toasterid)
{
	Datum toast_options;
	List    *defList = NIL;
	static char *validnsps[] = HEAP_RELOPT_NAMESPACES;

	defList = lappend(defList, makeDefElem("toasteroid", (Node *) makeInteger(toasterid), -1));
	defList = lappend(defList, makeDefElem("toastrelid", (Node *) makeInteger(relid), -1));

	toast_options = transformRelOptions(reloptions,
									 defList, NULL, validnsps, false,
									 false);

	(void) heap_reloptions(RELKIND_TOASTVALUE, toast_options, false);
	return toast_options;
}

Datum
attopts_get_toaster_opts(Oid relOid, char *attname, int attnum, char *optname)
{
	List *o_list = NIL;
	ListCell   *cell;
	Datum o_datum;
	int l_idx = 0;
	char *str = NULL;

	o_datum = get_attoptions(relOid, attnum);
   if(o_datum == (Datum) 0)
      return (Datum) 0;

   o_list =  untransformRelOptions(o_datum);

	foreach(cell, o_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);
		l_idx++;
		elog(NOTICE, "att <%s>", def->defname);
		if (strcmp(def->defname, optname) == 0)
		{
			str = palloc(strlen(defGetString(def)));
			memcpy(str, defGetString(def), strlen(defGetString(def)));
			break;
		}
	}
	pfree(o_list);
	pfree(DatumGetPointer(o_datum));
	if(str == NULL)
		return (Datum) 0;
	return CStringGetDatum(str);
}


Datum
attopts_set_toaster_opts(Oid relOid, char *attname, char *optname, char *optval)
{
	Relation	attrelation;
	HeapTuple	tuple,
				newtuple;
	Form_pg_attribute attrtuple;
	AttrNumber	attnum;
	bool		isnull;
	Datum		repl_val[Natts_pg_attribute];
	bool		repl_null[Natts_pg_attribute];
	bool		repl_repl[Natts_pg_attribute];
	Datum opts, o_datum;
	List *o_list;
	ListCell *cell;
	int l_idx = 0;
	Datum res = (Datum) 0;

	attrelation = table_open(AttributeRelationId, RowExclusiveLock);
	tuple = SearchSysCacheAttName(relOid, attname);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						attname, RelationGetRelationName(attrelation))));

	attrtuple = (Form_pg_attribute) GETSTRUCT(tuple);

	attnum = attrtuple->attnum;
	if (attnum <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("cannot alter system column \"%s\"",
						attname)));
	o_datum = SysCacheGetAttr(ATTNAME, tuple, Anum_pg_attribute_attoptions,
							&isnull);

	o_list = untransformRelOptions(o_datum);

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	l_idx = 0;

	foreach(cell, o_list)
	{
		DefElem    *def = (DefElem *) lfirst(cell);
		l_idx++;
		if (strcmp(def->defname, optname) == 0)
			o_list = list_delete_nth_cell(o_list, l_idx);
	}

	o_list = lappend(o_list, makeDefElem(optname, (Node *) makeString(optval), -1));
	opts = transformRelOptions(isnull ? (Datum) 0 : o_datum,
									 o_list, NULL, NULL, false,
									 false);	

	if (opts != (Datum) 0)
		repl_val[Anum_pg_attribute_attoptions - 1] = opts;
	else
		repl_null[Anum_pg_attribute_attoptions - 1] = true;
	repl_repl[Anum_pg_attribute_attoptions - 1] = true;
	newtuple = heap_modify_tuple(tuple, RelationGetDescr(attrelation),
								 repl_val, repl_null, repl_repl);
	CatalogTupleUpdate(attrelation, &newtuple->t_self, newtuple);

	heap_freetuple(newtuple);

	ReleaseSysCache(tuple);

	table_close(attrelation, RowExclusiveLock);
	CommandCounterIncrement();
	return res;

}

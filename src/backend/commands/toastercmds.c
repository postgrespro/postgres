/*-------------------------------------------------------------------------
 *
 * toastercmds.c
 *	  Routines for SQL commands that manipulate toasters.
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/commands/toastercmds.c
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_toaster.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "miscadmin.h"
#include "parser/parse_func.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"


static Oid	lookup_toaster_handler_func(List *handler_name);

/*
 * CreateToaster
 *		Registers a new toaster.
 */
ObjectAddress
CreateToaster(CreateToasterStmt *stmt)
{
	Relation	rel;
	ObjectAddress myself;
	ObjectAddress referenced;
	Oid			tsroid;
	Oid			tsrhandler;
	bool		nulls[Natts_pg_toaster];
	Datum		values[Natts_pg_toaster];
	HeapTuple	tup;

	rel = table_open(ToasterRelationId, RowExclusiveLock);

	/* Must be superuser */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create toaster \"%s\"",
						stmt->tsrname),
				 errhint("Must be superuser to create an toaster.")));

	/* Check if name is used */
	tsroid = GetSysCacheOid1(TOASTERNAME, Anum_pg_toaster_oid,
							CStringGetDatum(stmt->tsrname));
	if (OidIsValid(tsroid))
	{
		if (stmt->if_not_exists)
		{
			ereport(NOTICE,
					(errcode(ERRCODE_DUPLICATE_OBJECT),
					 errmsg("toaster \"%s\" already exists, skipping",
							stmt->tsrname)));

			table_close(rel, RowExclusiveLock);
			return InvalidObjectAddress;
		}
		else
			ereport(ERROR,
					(errcode(ERRCODE_DUPLICATE_OBJECT),
					 errmsg("toaster \"%s\" already exists",
							stmt->tsrname)));
	}

	/*
	 * Get the handler function oid, verifying the toaster type while at it.
	 */
	tsrhandler = lookup_toaster_handler_func(stmt->handler_name);

	/*
	 * Insert tuple into pg_toaster.
	 */
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	tsroid = GetNewOidWithIndex(rel, ToasterOidIndexId, Anum_pg_toaster_oid);
	values[Anum_pg_toaster_oid - 1] = ObjectIdGetDatum(tsroid);
	values[Anum_pg_toaster_tsrname - 1] =
		DirectFunctionCall1(namein, CStringGetDatum(stmt->tsrname));
	values[Anum_pg_toaster_tsrhandler - 1] = ObjectIdGetDatum(tsrhandler);

	tup = heap_form_tuple(RelationGetDescr(rel), values, nulls);

	CatalogTupleInsert(rel, tup);
	heap_freetuple(tup);

	myself.classId = ToasterRelationId;
	myself.objectId = tsroid;
	myself.objectSubId = 0;

	/* Record dependency on handler function */
	referenced.classId = ProcedureRelationId;
	referenced.objectId = tsrhandler;
	referenced.objectSubId = 0;

	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	recordDependencyOnCurrentExtension(&myself, false);

	InvokeObjectPostCreateHook(ToasterRelationId, tsroid, 0);

	table_close(rel, RowExclusiveLock);

	return myself;
}

/*
 * get_toaster_oid - given an toaster name, look up its OID
 */
Oid
get_toaster_oid(const char *tsrname, bool missing_ok)
{
	HeapTuple	tup;
	Oid			oid = InvalidOid;

	tup = SearchSysCache1(TOASTERNAME, CStringGetDatum(tsrname));
	if (HeapTupleIsValid(tup))
	{
		Form_pg_toaster	tsrform = (Form_pg_toaster) GETSTRUCT(tup);

		oid = tsrform->oid;
		ReleaseSysCache(tup);
	}

	if (!OidIsValid(oid) && !missing_ok)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("toaster \"%s\" does not exist", tsrname)));
	return oid;
}

/*
 * get_toaster_name - given an toaster OID, look up its name.
 */
char *
get_toaster_name(Oid tsroid)
{
	HeapTuple	tup;
	char	   *result = NULL;

	tup = SearchSysCache1(TOASTEROID, ObjectIdGetDatum(tsroid));
	if (HeapTupleIsValid(tup))
	{
		Form_pg_toaster	tsrform = (Form_pg_toaster) GETSTRUCT(tup);

		result = pstrdup(NameStr(tsrform->tsrname));
		ReleaseSysCache(tup);
	}
	return result;
}

/*
 * Convert a handler function name to an Oid.  If the return type of the
 * function doesn't match the given toaster type, an error is raised.
 *
 * This function either return valid function Oid or throw an error.
 */
static Oid
lookup_toaster_handler_func(List *handler_name)
{
	Oid			handlerOid;
	Oid			funcargtypes[1] = {INTERNALOID};

	if (handler_name == NIL)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("handler function is not specified")));

	/* handlers have one argument of type internal */
	handlerOid = LookupFuncName(handler_name, 1, funcargtypes, false);

	if (get_func_rettype(handlerOid) != TOASTER_HANDLEROID)
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("function %s must return type %s",
						get_func_name(handlerOid),
						format_type_extended(TOASTER_HANDLEROID, -1, 0))));

	return handlerOid;
}

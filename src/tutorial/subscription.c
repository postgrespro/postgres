/*
 * src/tutorial/subscription.c
 *
 ******************************************************************************
  This file contains routines that can be bound to a Postgres backend and
  called by the backend in the process of processing queries.  The calling
  format for these routines is dictated by Postgres architecture.
******************************************************************************/

#include "postgres.h"

#include "catalog/pg_type.h"
#include "executor/executor.h"
#include "nodes/execnodes.h"
#include "nodes/nodeFuncs.h"
#include "parser/parse_coerce.h"
#include "parser/parse_node.h"
#include "utils/array.h"
#include "fmgr.h"
#include "funcapi.h"

PG_MODULE_MAGIC;

typedef struct Custom
{
	int	first;
	int	second;
}	Custom;


/*****************************************************************************
 * Input/Output functions
 *****************************************************************************/

PG_FUNCTION_INFO_V1(custom_in);

Datum
custom_in(PG_FUNCTION_ARGS)
{
	char	*str = PG_GETARG_CSTRING(0);
	int		firstValue,
			secondValue;
	Custom	*result;

	if (sscanf(str, " ( %d , %d )", &firstValue, &secondValue) != 2)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for complex: \"%s\"",
						str)));


	result = (Custom *) palloc(sizeof(Custom));
	result->first = firstValue;
	result->second = secondValue;
	PG_RETURN_POINTER(result);
}

PG_FUNCTION_INFO_V1(custom_out);

Datum
custom_out(PG_FUNCTION_ARGS)
{
	Custom	*custom = (Custom *) PG_GETARG_POINTER(0);
	char	*result;

	result = psprintf("(%d, %d)", custom->first, custom->second);
	PG_RETURN_CSTRING(result);
}

/*****************************************************************************
 * Custom subscription logic functions
 *****************************************************************************/

Datum
custom_subscription_evaluate(PG_FUNCTION_ARGS)
{
	SubscriptionRefExprState	*sbstate = (SubscriptionRefExprState *) PG_GETARG_POINTER(0);
	SubscriptionExecData		*sbsdata = (SubscriptionExecData *) PG_GETARG_POINTER(1);
	SubscriptionRef				*custom_ref = (SubscriptionRef *) sbstate->xprstate.expr;
	Custom						*result = (Custom *) sbsdata->containerSource;
	bool						*is_null = sbsdata->isNull;
	bool						is_assignment = (custom_ref->refassgnexpr != NULL);

	int							index;

	if (sbsdata->indexprNumber != 1)
		ereport(ERROR, (errmsg("custom does not support nested subscription")));

	index = DatumGetInt32(sbsdata->upper[0]);

	if (is_assignment)
	{
		ExprContext	   *econtext = sbsdata->xprcontext;
		Datum			sourceData;
		Datum			save_datum;
		bool			save_isNull;
		bool			eisnull;

		/*
		 * We might have a nested-assignment situation, in which the
		 * refassgnexpr is itself a FieldStore or SubscriptionRef that needs to
		 * obtain and modify the previous value of the array element or slice
		 * being replaced.  If so, we have to extract that value from the
		 * array and pass it down via the econtext's caseValue.  It's safe to
		 * reuse the CASE mechanism because there cannot be a CASE between
		 * here and where the value would be needed, and an array assignment
		 * can't be within a CASE either.  (So saving and restoring the
		 * caseValue is just paranoia, but let's do it anyway.)
		 *
		 * Since fetching the old element might be a nontrivial expense, do it
		 * only if the argument appears to actually need it.
		 */
		save_datum = econtext->caseValue_datum;
		save_isNull = econtext->caseValue_isNull;

		/*
		 * Evaluate the value to be assigned into the container.
		 */
		sourceData = ExecEvalExpr(sbstate->refassgnexpr,
								  econtext,
								  &eisnull,
								  NULL);

		econtext->caseValue_datum = save_datum;
		econtext->caseValue_isNull = save_isNull;

		/*
		 * For an assignment to a fixed-length array type, both the original
		 * array and the value to be assigned into it must be non-NULL, else
		 * we punt and return the original array.
		 */
		if (sbstate->refattrlength > 0)	/* fixed-length container? */
			if (eisnull || *is_null)
				return sbsdata->containerSource;

		/*
		 * For assignment to varlena container, we handle a NULL original array
		 * by substituting an empty (zero-dimensional) array; insertion of the
		 * new element will result in a singleton array value.  It does not
		 * matter whether the new element is NULL.
		 */
		if (*is_null)
		{
			sbsdata->containerSource =
				PointerGetDatum(construct_empty_array(custom_ref->refelemtype));
			*is_null = false;
		}

		if (index == 1)
			result->first = DatumGetInt32(sourceData);
		else
			result->second = DatumGetInt32(sourceData);

		PG_RETURN_POINTER(result);
	}
	else
	{
		if (index == 1)
			PG_RETURN_INT32(result->first);
		else
			PG_RETURN_INT32(result->second);
	}
}

Datum
custom_subscription_prepare(PG_FUNCTION_ARGS)
{
	SubscriptionRef	   *sbsref = (SubscriptionRef *) PG_GETARG_POINTER(0);
	ParseState		   *pstate = (ParseState *) PG_GETARG_POINTER(1);
	List			   *upperIndexpr = NIL;
	ListCell		   *l;

	if (sbsref->reflowerindexpr != NIL)
		ereport(ERROR,
				(errcode(ERRCODE_DATATYPE_MISMATCH),
				 errmsg("custom subscript does not support slices"),
				 parser_errposition(pstate, exprLocation(
						 ((Node *)lfirst(sbsref->reflowerindexpr->head))))));

	foreach(l, sbsref->refupperindexpr)
	{
		Node *subexpr = (Node *) lfirst(l);

		Assert(subexpr != NULL);

		if (subexpr == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_DATATYPE_MISMATCH),
					 errmsg("custom subscript does not support slices"),
					 parser_errposition(pstate, exprLocation(
						((Node *) lfirst(sbsref->refupperindexpr->head))))));

		subexpr = coerce_to_target_type(pstate,
										subexpr, exprType(subexpr),
										INT4OID, -1,
										COERCION_ASSIGNMENT,
										COERCE_IMPLICIT_CAST,
										-1);
		if (subexpr == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_DATATYPE_MISMATCH),
					 errmsg("custom subscript must have int type"),
					 parser_errposition(pstate, exprLocation(subexpr))));

		upperIndexpr = lappend(upperIndexpr, subexpr);
	}

	sbsref->refupperindexpr = upperIndexpr;
	sbsref->refelemtype = INT4OID;

	PG_RETURN_POINTER(sbsref);
}

PG_FUNCTION_INFO_V1(custom_subscription);

Datum
custom_subscription(PG_FUNCTION_ARGS)
{
	int						op_type = PG_GETARG_INT32(0);
	FunctionCallInfoData	target_fcinfo = get_slice_arguments(fcinfo, 1,
																fcinfo->nargs);

	if (op_type & SBS_VALIDATION)
		return custom_subscription_prepare(&target_fcinfo);

	if (op_type & SBS_EXEC)
		return custom_subscription_evaluate(&target_fcinfo);

	elog(ERROR, "incorrect op_type for subscription function: %d", op_type);
}

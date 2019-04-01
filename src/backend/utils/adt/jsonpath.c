/*-------------------------------------------------------------------------
 *
 * jsonpath.c
 *	 Input/output and supporting routines for jsonpath
 *
 * jsonpath expression is a chain of path items.  First path item is $, $var,
 * literal or arithmetic expression.  Subsequent path items are accessors
 * (.key, .*, [subscripts], [*]), filters (? (predicate)) and methods (.type(),
 * .size() etc).
 *
 * For instance, structure of path items for simple expression:
 *
 *		$.a[*].type()
 *
 * is pretty evident:
 *
 *		$ => .a => [*] => .type()
 *
 * Some path items such as arithmetic operations, predicates or array
 * subscripts may comprise subtrees.  For instance, more complex expression
 *
 *		($.a + $[1 to 5, 7] ? (@ > 3).double()).type()
 *
 * have following structure of path items:
 *
 *			  +  =>  .type()
 *		  ___/ \___
 *		 /		   \
 *		$ => .a 	$  =>  []  =>	?  =>  .double()
 *						  _||_		|
 *						 /	  \ 	>
 *						to	  to   / \
 *					   / \	  /   @   3
 *					  1   5  7
 *
 * Binary encoding of jsonpath constitutes a sequence of 4-bytes aligned
 * variable-length path items connected by links.  Every item has a header
 * consisting of item type (enum JsonPathItemType) and offset of next item
 * (zero means no next item).  After the header, item may have payload
 * depending on item type.  For instance, payload of '.key' accessor item is
 * length of key name and key name itself.  Payload of '>' arithmetic operator
 * item is offsets of right and left operands.
 *
 * So, binary representation of sample expression above is:
 * (bottom arrows are next links, top lines are argument links)
 *
 *								  _____
 *		 _____				  ___/____ \				__
 *	  _ /_	  \ 		_____/__/____ \ \	   __    _ /_ \
 *	 / /  \    \	   /	/  /	 \ \ \ 	  /  \  / /  \ \
 * +(LR)  $ .a	$  [](* to *, * to *) 1 5 7 ?(A)  >(LR)   @ 3 .double() .type()
 * |	  |  ^	|  ^|						 ^|					  ^		   ^
 * |	  |__|	|__||________________________||___________________|		   |
 * |_______________________________________________________________________|
 *
 * Copyright (c) 2019-2020, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	src/backend/utils/adt/jsonpath.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "catalog/pg_type_d.h"
#include "catalog/pg_operator_d.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/supportnodes.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/json.h"
#include "utils/jsonpath.h"

typedef struct JsonPathContext
{
	StringInfo	buf;
	Jsonb	   *vars;
	bool		varsCantBeSubstituted;
} JsonPathContext;

static Datum jsonPathFromCstring(char *in, int len);
static char *jsonPathToCstring(StringInfo out, JsonPath *in,
							   int estimated_len);
static JsonPath *encodeJsonPath(JsonPathParseItem *item, bool lax,
								int32 sizeEstimation, Jsonb *vars);
static int	flattenJsonPathParseItem(JsonPathContext *cxt, JsonPathParseItem *item,
									 int nestingLevel, bool insideArraySubscript);
static int32 copyJsonPathItem(JsonPathContext *cxt, JsonPathItem *item,
							  int32 *pLastOffset, int32 *pNextOffset);
static void alignStringInfoInt(StringInfo buf);
static int32 reserveSpaceForItemPointer(StringInfo buf);
static void printJsonPathItem(StringInfo buf, JsonPathItem *v, bool inKey,
							  bool printBracketes);
static int	operationPriority(JsonPathItemType op);
static bool replaceVariableReference(JsonPathContext *cxt, JsonPathItem *var,
						 int32 pos);
static JsonPath *substituteVariables(JsonPath *jsp, Jsonb *vars);
static Node *jsonb_path_support(Node *rawreq, bool exists);

/**************************** INPUT/OUTPUT ********************************/

/*
 * jsonpath type input function
 */
Datum
jsonpath_in(PG_FUNCTION_ARGS)
{
	char	   *in = PG_GETARG_CSTRING(0);
	int			len = strlen(in);

	return jsonPathFromCstring(in, len);
}

/*
 * jsonpath type recv function
 *
 * The type is sent as text in binary mode, so this is almost the same
 * as the input function, but it's prefixed with a version number so we
 * can change the binary format sent in future if necessary. For now,
 * only version 1 is supported.
 */
Datum
jsonpath_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	int			version = pq_getmsgint(buf, 1);
	char	   *str;
	int			nbytes;

	if (version == JSONPATH_VERSION)
		str = pq_getmsgtext(buf, buf->len - buf->cursor, &nbytes);
	else
		elog(ERROR, "unsupported jsonpath version number: %d", version);

	return jsonPathFromCstring(str, nbytes);
}

/*
 * jsonpath type output function
 */
Datum
jsonpath_out(PG_FUNCTION_ARGS)
{
	JsonPath   *in = PG_GETARG_JSONPATH_P(0);

	PG_RETURN_CSTRING(jsonPathToCstring(NULL, in, VARSIZE(in)));
}

/*
 * jsonpath type send function
 *
 * Just send jsonpath as a version number, then a string of text
 */
Datum
jsonpath_send(PG_FUNCTION_ARGS)
{
	JsonPath   *in = PG_GETARG_JSONPATH_P(0);
	StringInfoData buf;
	StringInfoData jtext;
	int			version = JSONPATH_VERSION;

	initStringInfo(&jtext);
	(void) jsonPathToCstring(&jtext, in, VARSIZE(in));

	pq_begintypsend(&buf);
	pq_sendint8(&buf, version);
	pq_sendtext(&buf, jtext.data, jtext.len);
	pfree(jtext.data);

	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

Datum
jsonpath_embed_vars(PG_FUNCTION_ARGS)
{
	JsonPath   *jsp = PG_GETARG_JSONPATH_P(0);
	Jsonb	   *vars = PG_GETARG_JSONB_P(1);

	if (!(jsp = substituteVariables(jsp, vars)))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("cannot embed jsonpath variables")));

	PG_RETURN_JSONPATH_P(jsp);
}

/* Planner support for jsonb_path_match() */
Datum
jsonb_path_match_support(PG_FUNCTION_ARGS)
{
	Node       *rawreq = (Node *) PG_GETARG_POINTER(0);

	PG_RETURN_POINTER(jsonb_path_support(rawreq, false));
}

/* Planner support for jsonb_path_exists() */
Datum
jsonb_path_exists_support(PG_FUNCTION_ARGS)
{
	Node       *rawreq = (Node *) PG_GETARG_POINTER(0);

	PG_RETURN_POINTER(jsonb_path_support(rawreq, true));
}

/*
 * Converts C-string to a jsonpath value.
 *
 * Uses jsonpath parser to turn string into an AST, then
 * flattenJsonPathParseItem() does second pass turning AST into binary
 * representation of jsonpath.
 */
static Datum
jsonPathFromCstring(char *in, int len)
{
	JsonPathParseResult *jsonpath = parsejsonpath(in, len);
	JsonPath   *res;

	if (!jsonpath)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for type %s: \"%s\"", "jsonpath",
						in)));

	res = encodeJsonPath(jsonpath->expr, jsonpath->lax,
						 4 * len /* estimation */ , NULL);

	PG_RETURN_JSONPATH_P(res);
}

static JsonPath *
encodeJsonPath(JsonPathParseItem *item, bool lax, int32 sizeEstimation,
			   Jsonb *vars)
{
	JsonPath   *res;
	JsonPathContext cxt;
	StringInfoData buf;

	if (!item)
		return NULL;

	initStringInfo(&buf);
	enlargeStringInfo(&buf, sizeEstimation);

	appendStringInfoSpaces(&buf, JSONPATH_HDRSZ);

	cxt.buf = &buf;
	cxt.vars = vars;
	cxt.varsCantBeSubstituted = false;

	flattenJsonPathParseItem(&cxt, item, 0, false);

	if (cxt.varsCantBeSubstituted)
		return NULL;

	res = (JsonPath *) buf.data;
	SET_VARSIZE(res, buf.len);
	res->header = JSONPATH_VERSION;
	if (lax)
		res->header |= JSONPATH_LAX;

	return res;
}

/*
 * Converts jsonpath value to a C-string.
 *
 * If 'out' argument is non-null, the resulting C-string is stored inside the
 * StringBuffer.  The resulting string is always returned.
 */
static char *
jsonPathToCstring(StringInfo out, JsonPath *in, int estimated_len)
{
	StringInfoData buf;
	JsonPathItem v;

	if (!out)
	{
		out = &buf;
		initStringInfo(out);
	}
	enlargeStringInfo(out, estimated_len);

	if (!(in->header & JSONPATH_LAX))
		appendBinaryStringInfo(out, "strict ", 7);

	jspInit(&v, in);
	printJsonPathItem(out, &v, false, true);

	return out->data;
}

/*****************************INPUT/OUTPUT************************************/

static inline int32
appendJsonPathItemHeader(StringInfo buf, JsonPathItemType type)
{
	appendStringInfoChar(buf, (char) type);

	/*
	 * We align buffer to int32 because a series of int32 values often goes
	 * after the header, and we want to read them directly by dereferencing
	 * int32 pointer (see jspInitByBuffer()).
	 */
	alignStringInfoInt(buf);

	/*
	 * Reserve space for next item pointer.  Actual value will be recorded
	 * later, after next and children items processing.
	 */
	return reserveSpaceForItemPointer(buf);
}

static int32
copyJsonPathItem(JsonPathContext *cxt, JsonPathItem *item,
				 int32 *pLastOffset, int32 *pNextOffset)
{
	StringInfo	buf = cxt->buf;
	int32		pos = buf->len - JSONPATH_HDRSZ;
	JsonPathItem next;
	int32		offs = 0;
	int32		nextOffs;

	check_stack_depth();

	nextOffs = appendJsonPathItemHeader(buf, item->type);

	switch (item->type)
	{
		case jpiNull:
		case jpiCurrent:
		case jpiAnyArray:
		case jpiAnyKey:
		case jpiType:
		case jpiSize:
		case jpiAbs:
		case jpiFloor:
		case jpiCeiling:
		case jpiDouble:
		case jpiKeyValue:
		case jpiLast:
			break;

		case jpiRoot:
			break;

		case jpiKey:
		case jpiString:
		case jpiVariable:
			{
				int32		len;
				char	   *data = jspGetString(item, &len);

				if (item->type == jpiVariable && cxt->vars &&
					replaceVariableReference(cxt, item, pos))
					break;

				appendBinaryStringInfo(buf, (const char *) &len, sizeof(len));
				appendBinaryStringInfo(buf, data, len);
				appendStringInfoChar(buf, '\0');
				break;
			}

		case jpiNumeric:
			{
				Numeric		num = jspGetNumeric(item);

				appendBinaryStringInfo(buf, (char *) num, VARSIZE(num));
				break;
			}

		case jpiBool:
			appendStringInfoChar(buf, jspGetBool(item) ? 1 : 0);
			break;

		case jpiFilter:
		case jpiNot:
		case jpiExists:
		case jpiIsUnknown:
		case jpiPlus:
		case jpiMinus:
			{
				JsonPathItem arg;
				int32		argoffs;
				int32		argpos;

				argoffs = buf->len;
				appendBinaryStringInfo(buf, (const char *) &offs, sizeof(offs));

				if (!item->content.arg)
					break;

				jspGetArg(item, &arg);
				argpos = copyJsonPathItem(cxt, &arg, NULL, NULL);
				*(int32 *) &buf->data[argoffs] = argpos - pos;
				break;
			}

		case jpiAnd:
		case jpiOr:
		case jpiAdd:
		case jpiSub:
		case jpiMul:
		case jpiDiv:
		case jpiMod:
		case jpiEqual:
		case jpiNotEqual:
		case jpiLess:
		case jpiGreater:
		case jpiLessOrEqual:
		case jpiGreaterOrEqual:
		case jpiStartsWith:
			{
				JsonPathItem larg;
				JsonPathItem rarg;
				int32		loffs;
				int32		roffs;
				int32		lpos;
				int32		rpos;

				loffs = buf->len;
				appendBinaryStringInfo(buf, (const char *) &offs, sizeof(offs));

				roffs = buf->len;
				appendBinaryStringInfo(buf, (const char *) &offs, sizeof(offs));

				jspGetLeftArg(item, &larg);
				lpos = copyJsonPathItem(cxt, &larg, NULL, NULL);
				*(int32 *) &buf->data[loffs] = lpos - pos;

				jspGetRightArg(item, &rarg);
				rpos = copyJsonPathItem(cxt, &rarg, NULL, NULL);
				*(int32 *) &buf->data[roffs] = rpos - pos;

				break;
			}

		case jpiLikeRegex:
			{
				JsonPathItem expr;
				int32		eoffs;
				int32		epos;

				appendBinaryStringInfo(buf,
									(char *) &item->content.like_regex.flags,
									sizeof(item->content.like_regex.flags));

				eoffs = buf->len;
				appendBinaryStringInfo(buf, (char *) &offs /* fake value */, sizeof(offs));

				appendBinaryStringInfo(buf,
									(char *) &item->content.like_regex.patternlen,
									sizeof(item->content.like_regex.patternlen));
				appendBinaryStringInfo(buf, item->content.like_regex.pattern,
									   item->content.like_regex.patternlen);
				appendStringInfoChar(buf, '\0');

				jspInitByBuffer(&expr, item->base, item->content.like_regex.expr);
				epos = copyJsonPathItem(cxt, &expr, NULL, NULL);
				*(int32 *) &buf->data[eoffs] = epos - pos;
			}
			break;

		case jpiIndexArray:
			{
				int32		nelems = item->content.array.nelems;
				int32		i;
				int			offset;

				appendBinaryStringInfo(buf, (char *) &nelems, sizeof(nelems));
				offset = buf->len;
				appendStringInfoSpaces(buf, sizeof(int32) * 2 * nelems);

				for (i = 0; i < nelems; i++, offset += 2 * sizeof(int32))
				{
					JsonPathItem from;
					JsonPathItem to;
					int32	   *ppos;
					int32		frompos;
					int32		topos;
					bool		range;

					range = jspGetArraySubscript(item, &from, &to, i);

					frompos = copyJsonPathItem(cxt, &from, NULL, NULL) - pos;

					if (range)
						topos = copyJsonPathItem(cxt, &to, NULL, NULL) - pos;
					else
						topos = 0;

					ppos = (int32 *) &buf->data[offset];
					ppos[0] = frompos;
					ppos[1] = topos;
				}
			}
			break;

		case jpiAny:
			appendBinaryStringInfo(buf, (char *) &item->content.anybounds.first,
								   sizeof(item->content.anybounds.first));
			appendBinaryStringInfo(buf, (char *) &item->content.anybounds.last,
								   sizeof(item->content.anybounds.last));
			break;

		default:
			elog(ERROR, "Unknown jsonpath item type: %d", item->type);
	}

	if (jspGetNext(item, &next))
	{
		int32		nextPos = copyJsonPathItem(cxt, &next,
											   pLastOffset, pNextOffset);

		*(int32 *) &buf->data[nextOffs] = nextPos - pos;
	}
	else if (pLastOffset)
	{
		*pLastOffset = pos;
		*pNextOffset = nextOffs;
	}

	return pos;
}

static int32
copyJsonPath(JsonPathContext *cxt, JsonPath *jp, int32 *last, int32 *next)
{
	JsonPathItem root;

	alignStringInfoInt(cxt->buf);

	jspInit(&root, jp);

	return copyJsonPathItem(cxt, &root, last, next);
}

/*
 * Recursive function converting given jsonpath parse item and all its
 * children into a binary representation.
 */
static int
flattenJsonPathParseItem(JsonPathContext *cxt, JsonPathParseItem *item,
						 int nestingLevel, bool insideArraySubscript)
{
	StringInfo	buf = cxt->buf;
	/* position from beginning of jsonpath data */
	int32		pos = buf->len - JSONPATH_HDRSZ;
	int32		chld;
	int32		next;
	int32		last;
	int			argNestingLevel = nestingLevel;

	check_stack_depth();
	CHECK_FOR_INTERRUPTS();

	if (item->type == jpiBinary)
	{
		Assert(!nestingLevel);
		pos = copyJsonPath(cxt, item->value.binary, &last, &next);
	}
	else
	{
		next = appendJsonPathItemHeader(buf, item->type);
		last = pos;
	}

	switch (item->type)
	{
		case jpiBinary:
			break;
		case jpiString:
		case jpiVariable:
		case jpiKey:
			appendBinaryStringInfo(buf, (char *) &item->value.string.len,
								   sizeof(item->value.string.len));
			appendBinaryStringInfo(buf, item->value.string.val,
								   item->value.string.len);
			appendStringInfoChar(buf, '\0');
			break;
		case jpiNumeric:
			appendBinaryStringInfo(buf, (char *) item->value.numeric,
								   VARSIZE(item->value.numeric));
			break;
		case jpiBool:
			appendBinaryStringInfo(buf, (char *) &item->value.boolean,
								   sizeof(item->value.boolean));
			break;
		case jpiAnd:
		case jpiOr:
		case jpiEqual:
		case jpiNotEqual:
		case jpiLess:
		case jpiGreater:
		case jpiLessOrEqual:
		case jpiGreaterOrEqual:
		case jpiAdd:
		case jpiSub:
		case jpiMul:
		case jpiDiv:
		case jpiMod:
		case jpiStartsWith:
			{
				/*
				 * First, reserve place for left/right arg's positions, then
				 * record both args and sets actual position in reserved
				 * places.
				 */
				int32		left = reserveSpaceForItemPointer(buf);
				int32		right = reserveSpaceForItemPointer(buf);

				chld = !item->value.args.left ? pos :
					flattenJsonPathParseItem(cxt, item->value.args.left,
											 argNestingLevel,
											 insideArraySubscript);
				*(int32 *) (buf->data + left) = chld - pos;

				chld = !item->value.args.right ? pos :
					flattenJsonPathParseItem(cxt, item->value.args.right,
											 argNestingLevel,
											 insideArraySubscript);
				*(int32 *) (buf->data + right) = chld - pos;
			}
			break;
		case jpiLikeRegex:
			{
				int32		offs;

				appendBinaryStringInfo(buf,
									   (char *) &item->value.like_regex.flags,
									   sizeof(item->value.like_regex.flags));
				offs = reserveSpaceForItemPointer(buf);
				appendBinaryStringInfo(buf,
									   (char *) &item->value.like_regex.patternlen,
									   sizeof(item->value.like_regex.patternlen));
				appendBinaryStringInfo(buf, item->value.like_regex.pattern,
									   item->value.like_regex.patternlen);
				appendStringInfoChar(buf, '\0');

				chld = flattenJsonPathParseItem(cxt, item->value.like_regex.expr,
												nestingLevel,
												insideArraySubscript);
				*(int32 *) (buf->data + offs) = chld - pos;
			}
			break;
		case jpiFilter:
			argNestingLevel++;
			/* FALLTHROUGH */
		case jpiIsUnknown:
		case jpiNot:
		case jpiPlus:
		case jpiMinus:
		case jpiExists:
		case jpiDatetime:
			{
				int32		arg = reserveSpaceForItemPointer(buf);

				chld = !item->value.arg ? pos :
					flattenJsonPathParseItem(cxt, item->value.arg,
											 argNestingLevel,
											 insideArraySubscript);
				*(int32 *) (buf->data + arg) = chld - pos;
			}
			break;
		case jpiNull:
			break;
		case jpiRoot:
			break;
		case jpiAnyArray:
		case jpiAnyKey:
			break;
		case jpiCurrent:
			if (nestingLevel <= 0)
				ereport(ERROR,
						(errcode(ERRCODE_SYNTAX_ERROR),
						 errmsg("@ is not allowed in root expressions")));
			break;
		case jpiLast:
			if (!insideArraySubscript)
				ereport(ERROR,
						(errcode(ERRCODE_SYNTAX_ERROR),
						 errmsg("LAST is allowed only in array subscripts")));
			break;
		case jpiIndexArray:
			{
				int32		nelems = item->value.array.nelems;
				int			offset;
				int			i;

				appendBinaryStringInfo(buf, (char *) &nelems, sizeof(nelems));

				offset = buf->len;

				appendStringInfoSpaces(buf, sizeof(int32) * 2 * nelems);

				for (i = 0; i < nelems; i++)
				{
					int32	   *ppos;
					int32		topos;
					int32		frompos =
					flattenJsonPathParseItem(cxt,
											item->value.array.elems[i].from,
											nestingLevel, true) - pos;

					if (item->value.array.elems[i].to)
						topos = flattenJsonPathParseItem(cxt,
														 item->value.array.elems[i].to,
														 nestingLevel, true) - pos;
					else
						topos = 0;

					ppos = (int32 *) &buf->data[offset + i * 2 * sizeof(int32)];

					ppos[0] = frompos;
					ppos[1] = topos;
				}
			}
			break;
		case jpiAny:
			appendBinaryStringInfo(buf,
								   (char *) &item->value.anybounds.first,
								   sizeof(item->value.anybounds.first));
			appendBinaryStringInfo(buf,
								   (char *) &item->value.anybounds.last,
								   sizeof(item->value.anybounds.last));
			break;
		case jpiType:
		case jpiSize:
		case jpiAbs:
		case jpiFloor:
		case jpiCeiling:
		case jpiDouble:
		case jpiKeyValue:
			break;
		default:
			elog(ERROR, "unrecognized jsonpath item type: %d", item->type);
	}

	if (item->next)
	{
		chld = flattenJsonPathParseItem(cxt, item->next, nestingLevel,
										insideArraySubscript) - last;
		*(int32 *) (buf->data + next) = chld;
	}

	return pos;
}

/*
 * Align StringInfo to int by adding zero padding bytes
 */
static void
alignStringInfoInt(StringInfo buf)
{
	switch (INTALIGN(buf->len) - buf->len)
	{
		case 3:
			appendStringInfoCharMacro(buf, 0);
			/* FALLTHROUGH */
		case 2:
			appendStringInfoCharMacro(buf, 0);
			/* FALLTHROUGH */
		case 1:
			appendStringInfoCharMacro(buf, 0);
			/* FALLTHROUGH */
		default:
			break;
	}
}

/*
 * Reserve space for int32 JsonPathItem pointer.  Now zero pointer is written,
 * actual value will be recorded at '(int32 *) &buf->data[pos]' later.
 */
static int32
reserveSpaceForItemPointer(StringInfo buf)
{
	int32		pos = buf->len;
	int32		ptr = 0;

	appendBinaryStringInfo(buf, (char *) &ptr, sizeof(ptr));

	return pos;
}

/*
 * Prints text representation of given jsonpath item and all its children.
 */
static void
printJsonPathItem(StringInfo buf, JsonPathItem *v, bool inKey,
				  bool printBracketes)
{
	JsonPathItem elem;
	int			i;

	check_stack_depth();
	CHECK_FOR_INTERRUPTS();

	switch (v->type)
	{
		case jpiNull:
			appendStringInfoString(buf, "null");
			break;
		case jpiKey:
			if (inKey)
				appendStringInfoChar(buf, '.');
			escape_json(buf, jspGetString(v, NULL));
			break;
		case jpiString:
			escape_json(buf, jspGetString(v, NULL));
			break;
		case jpiVariable:
			appendStringInfoChar(buf, '$');
			escape_json(buf, jspGetString(v, NULL));
			break;
		case jpiNumeric:
			appendStringInfoString(buf,
								   DatumGetCString(DirectFunctionCall1(numeric_out,
																	   NumericGetDatum(jspGetNumeric(v)))));
			break;
		case jpiBool:
			if (jspGetBool(v))
				appendBinaryStringInfo(buf, "true", 4);
			else
				appendBinaryStringInfo(buf, "false", 5);
			break;
		case jpiAnd:
		case jpiOr:
		case jpiEqual:
		case jpiNotEqual:
		case jpiLess:
		case jpiGreater:
		case jpiLessOrEqual:
		case jpiGreaterOrEqual:
		case jpiAdd:
		case jpiSub:
		case jpiMul:
		case jpiDiv:
		case jpiMod:
		case jpiStartsWith:
			if (printBracketes)
				appendStringInfoChar(buf, '(');
			jspGetLeftArg(v, &elem);
			printJsonPathItem(buf, &elem, false,
							  operationPriority(elem.type) <=
							  operationPriority(v->type));
			appendStringInfoChar(buf, ' ');
			appendStringInfoString(buf, jspOperationName(v->type));
			appendStringInfoChar(buf, ' ');
			jspGetRightArg(v, &elem);
			printJsonPathItem(buf, &elem, false,
							  operationPriority(elem.type) <=
							  operationPriority(v->type));
			if (printBracketes)
				appendStringInfoChar(buf, ')');
			break;
		case jpiLikeRegex:
			if (printBracketes)
				appendStringInfoChar(buf, '(');

			jspInitByBuffer(&elem, v->base, v->content.like_regex.expr);
			printJsonPathItem(buf, &elem, false,
							  operationPriority(elem.type) <=
							  operationPriority(v->type));

			appendBinaryStringInfo(buf, " like_regex ", 12);

			escape_json(buf, v->content.like_regex.pattern);

			if (v->content.like_regex.flags)
			{
				appendBinaryStringInfo(buf, " flag \"", 7);

				if (v->content.like_regex.flags & JSP_REGEX_ICASE)
					appendStringInfoChar(buf, 'i');
				if (v->content.like_regex.flags & JSP_REGEX_DOTALL)
					appendStringInfoChar(buf, 's');
				if (v->content.like_regex.flags & JSP_REGEX_MLINE)
					appendStringInfoChar(buf, 'm');
				if (v->content.like_regex.flags & JSP_REGEX_WSPACE)
					appendStringInfoChar(buf, 'x');
				if (v->content.like_regex.flags & JSP_REGEX_QUOTE)
					appendStringInfoChar(buf, 'q');

				appendStringInfoChar(buf, '"');
			}

			if (printBracketes)
				appendStringInfoChar(buf, ')');
			break;
		case jpiPlus:
		case jpiMinus:
			if (printBracketes)
				appendStringInfoChar(buf, '(');
			appendStringInfoChar(buf, v->type == jpiPlus ? '+' : '-');
			jspGetArg(v, &elem);
			printJsonPathItem(buf, &elem, false,
							  operationPriority(elem.type) <=
							  operationPriority(v->type));
			if (printBracketes)
				appendStringInfoChar(buf, ')');
			break;
		case jpiFilter:
			appendBinaryStringInfo(buf, "?(", 2);
			jspGetArg(v, &elem);
			printJsonPathItem(buf, &elem, false, false);
			appendStringInfoChar(buf, ')');
			break;
		case jpiNot:
			appendBinaryStringInfo(buf, "!(", 2);
			jspGetArg(v, &elem);
			printJsonPathItem(buf, &elem, false, false);
			appendStringInfoChar(buf, ')');
			break;
		case jpiIsUnknown:
			appendStringInfoChar(buf, '(');
			jspGetArg(v, &elem);
			printJsonPathItem(buf, &elem, false, false);
			appendBinaryStringInfo(buf, ") is unknown", 12);
			break;
		case jpiExists:
			appendBinaryStringInfo(buf, "exists (", 8);
			jspGetArg(v, &elem);
			printJsonPathItem(buf, &elem, false, false);
			appendStringInfoChar(buf, ')');
			break;
		case jpiCurrent:
			Assert(!inKey);
			appendStringInfoChar(buf, '@');
			break;
		case jpiRoot:
			Assert(!inKey);
			appendStringInfoChar(buf, '$');
			break;
		case jpiLast:
			appendBinaryStringInfo(buf, "last", 4);
			break;
		case jpiAnyArray:
			appendBinaryStringInfo(buf, "[*]", 3);
			break;
		case jpiAnyKey:
			if (inKey)
				appendStringInfoChar(buf, '.');
			appendStringInfoChar(buf, '*');
			break;
		case jpiIndexArray:
			appendStringInfoChar(buf, '[');
			for (i = 0; i < v->content.array.nelems; i++)
			{
				JsonPathItem from;
				JsonPathItem to;
				bool		range = jspGetArraySubscript(v, &from, &to, i);

				if (i)
					appendStringInfoChar(buf, ',');

				printJsonPathItem(buf, &from, false, false);

				if (range)
				{
					appendBinaryStringInfo(buf, " to ", 4);
					printJsonPathItem(buf, &to, false, false);
				}
			}
			appendStringInfoChar(buf, ']');
			break;
		case jpiAny:
			if (inKey)
				appendStringInfoChar(buf, '.');

			if (v->content.anybounds.first == 0 &&
				v->content.anybounds.last == PG_UINT32_MAX)
				appendBinaryStringInfo(buf, "**", 2);
			else if (v->content.anybounds.first == v->content.anybounds.last)
			{
				if (v->content.anybounds.first == PG_UINT32_MAX)
					appendStringInfo(buf, "**{last}");
				else
					appendStringInfo(buf, "**{%u}",
									 v->content.anybounds.first);
			}
			else if (v->content.anybounds.first == PG_UINT32_MAX)
				appendStringInfo(buf, "**{last to %u}",
								 v->content.anybounds.last);
			else if (v->content.anybounds.last == PG_UINT32_MAX)
				appendStringInfo(buf, "**{%u to last}",
								 v->content.anybounds.first);
			else
				appendStringInfo(buf, "**{%u to %u}",
								 v->content.anybounds.first,
								 v->content.anybounds.last);
			break;
		case jpiType:
			appendBinaryStringInfo(buf, ".type()", 7);
			break;
		case jpiSize:
			appendBinaryStringInfo(buf, ".size()", 7);
			break;
		case jpiAbs:
			appendBinaryStringInfo(buf, ".abs()", 6);
			break;
		case jpiFloor:
			appendBinaryStringInfo(buf, ".floor()", 8);
			break;
		case jpiCeiling:
			appendBinaryStringInfo(buf, ".ceiling()", 10);
			break;
		case jpiDouble:
			appendBinaryStringInfo(buf, ".double()", 9);
			break;
		case jpiDatetime:
			appendBinaryStringInfo(buf, ".datetime(", 10);
			if (v->content.arg)
			{
				jspGetArg(v, &elem);
				printJsonPathItem(buf, &elem, false, false);
			}
			appendStringInfoChar(buf, ')');
			break;
		case jpiKeyValue:
			appendBinaryStringInfo(buf, ".keyvalue()", 11);
			break;
		default:
			elog(ERROR, "unrecognized jsonpath item type: %d", v->type);
	}

	if (jspGetNext(v, &elem))
		printJsonPathItem(buf, &elem, true, true);
}

const char *
jspOperationName(JsonPathItemType type)
{
	switch (type)
	{
		case jpiAnd:
			return "&&";
		case jpiOr:
			return "||";
		case jpiEqual:
			return "==";
		case jpiNotEqual:
			return "!=";
		case jpiLess:
			return "<";
		case jpiGreater:
			return ">";
		case jpiLessOrEqual:
			return "<=";
		case jpiGreaterOrEqual:
			return ">=";
		case jpiPlus:
		case jpiAdd:
			return "+";
		case jpiMinus:
		case jpiSub:
			return "-";
		case jpiMul:
			return "*";
		case jpiDiv:
			return "/";
		case jpiMod:
			return "%";
		case jpiStartsWith:
			return "starts with";
		case jpiLikeRegex:
			return "like_regex";
		case jpiType:
			return "type";
		case jpiSize:
			return "size";
		case jpiKeyValue:
			return "keyvalue";
		case jpiDouble:
			return "double";
		case jpiAbs:
			return "abs";
		case jpiFloor:
			return "floor";
		case jpiCeiling:
			return "ceiling";
		case jpiDatetime:
			return "datetime";
		default:
			elog(ERROR, "unrecognized jsonpath item type: %d", type);
			return NULL;
	}
}

static int
operationPriority(JsonPathItemType op)
{
	switch (op)
	{
		case jpiOr:
			return 0;
		case jpiAnd:
			return 1;
		case jpiEqual:
		case jpiNotEqual:
		case jpiLess:
		case jpiGreater:
		case jpiLessOrEqual:
		case jpiGreaterOrEqual:
		case jpiStartsWith:
			return 2;
		case jpiAdd:
		case jpiSub:
			return 3;
		case jpiMul:
		case jpiDiv:
		case jpiMod:
			return 4;
		case jpiPlus:
		case jpiMinus:
			return 5;
		default:
			return 6;
	}
}

/******************* Support functions for JsonPath *************************/

/*
 * Support macros to read stored values
 */

#define read_byte(v, b, p) do {			\
	(v) = *(uint8*)((b) + (p));			\
	(p) += 1;							\
} while(0)								\

#define read_int32(v, b, p) do {		\
	(v) = *(uint32*)((b) + (p));		\
	(p) += sizeof(int32);				\
} while(0)								\

#define read_int32_n(v, b, p, n) do {	\
	(v) = (void *)((b) + (p));			\
	(p) += sizeof(int32) * (n);			\
} while(0)								\

/*
 * Read root node and fill root node representation
 */
void
jspInit(JsonPathItem *v, JsonPath *js)
{
	Assert((js->header & ~JSONPATH_LAX) == JSONPATH_VERSION);
	jspInitByBuffer(v, js->data, 0);
}

/*
 * Read node from buffer and fill its representation
 */
void
jspInitByBuffer(JsonPathItem *v, char *base, int32 pos)
{
	v->base = base + pos;

	read_byte(v->type, base, pos);
	pos = INTALIGN((uintptr_t) (base + pos)) - (uintptr_t) base;
	read_int32(v->nextPos, base, pos);

	switch (v->type)
	{
		case jpiNull:
		case jpiRoot:
		case jpiCurrent:
		case jpiAnyArray:
		case jpiAnyKey:
		case jpiType:
		case jpiSize:
		case jpiAbs:
		case jpiFloor:
		case jpiCeiling:
		case jpiDouble:
		case jpiKeyValue:
		case jpiLast:
			break;
		case jpiKey:
		case jpiString:
		case jpiVariable:
			read_int32(v->content.value.datalen, base, pos);
			/* FALLTHROUGH */
		case jpiNumeric:
		case jpiBool:
			v->content.value.data = base + pos;
			break;
		case jpiAnd:
		case jpiOr:
		case jpiAdd:
		case jpiSub:
		case jpiMul:
		case jpiDiv:
		case jpiMod:
		case jpiEqual:
		case jpiNotEqual:
		case jpiLess:
		case jpiGreater:
		case jpiLessOrEqual:
		case jpiGreaterOrEqual:
		case jpiStartsWith:
			read_int32(v->content.args.left, base, pos);
			read_int32(v->content.args.right, base, pos);
			break;
		case jpiLikeRegex:
			read_int32(v->content.like_regex.flags, base, pos);
			read_int32(v->content.like_regex.expr, base, pos);
			read_int32(v->content.like_regex.patternlen, base, pos);
			v->content.like_regex.pattern = base + pos;
			break;
		case jpiNot:
		case jpiExists:
		case jpiIsUnknown:
		case jpiPlus:
		case jpiMinus:
		case jpiFilter:
		case jpiDatetime:
			read_int32(v->content.arg, base, pos);
			break;
		case jpiIndexArray:
			read_int32(v->content.array.nelems, base, pos);
			read_int32_n(v->content.array.elems, base, pos,
						 v->content.array.nelems * 2);
			break;
		case jpiAny:
			read_int32(v->content.anybounds.first, base, pos);
			read_int32(v->content.anybounds.last, base, pos);
			break;
		default:
			elog(ERROR, "unrecognized jsonpath item type: %d", v->type);
	}
}

void
jspGetArg(JsonPathItem *v, JsonPathItem *a)
{
	Assert(v->type == jpiFilter ||
		   v->type == jpiNot ||
		   v->type == jpiIsUnknown ||
		   v->type == jpiExists ||
		   v->type == jpiPlus ||
		   v->type == jpiMinus ||
		   v->type == jpiDatetime);

	jspInitByBuffer(a, v->base, v->content.arg);
}

bool
jspGetNext(JsonPathItem *v, JsonPathItem *a)
{
	if (jspHasNext(v))
	{
		Assert(v->type == jpiString ||
			   v->type == jpiNumeric ||
			   v->type == jpiBool ||
			   v->type == jpiNull ||
			   v->type == jpiKey ||
			   v->type == jpiAny ||
			   v->type == jpiAnyArray ||
			   v->type == jpiAnyKey ||
			   v->type == jpiIndexArray ||
			   v->type == jpiFilter ||
			   v->type == jpiCurrent ||
			   v->type == jpiExists ||
			   v->type == jpiRoot ||
			   v->type == jpiVariable ||
			   v->type == jpiLast ||
			   v->type == jpiAdd ||
			   v->type == jpiSub ||
			   v->type == jpiMul ||
			   v->type == jpiDiv ||
			   v->type == jpiMod ||
			   v->type == jpiPlus ||
			   v->type == jpiMinus ||
			   v->type == jpiEqual ||
			   v->type == jpiNotEqual ||
			   v->type == jpiGreater ||
			   v->type == jpiGreaterOrEqual ||
			   v->type == jpiLess ||
			   v->type == jpiLessOrEqual ||
			   v->type == jpiAnd ||
			   v->type == jpiOr ||
			   v->type == jpiNot ||
			   v->type == jpiIsUnknown ||
			   v->type == jpiType ||
			   v->type == jpiSize ||
			   v->type == jpiAbs ||
			   v->type == jpiFloor ||
			   v->type == jpiCeiling ||
			   v->type == jpiDouble ||
			   v->type == jpiDatetime ||
			   v->type == jpiKeyValue ||
			   v->type == jpiStartsWith);

		if (a)
			jspInitByBuffer(a, v->base, v->nextPos);
		return true;
	}

	return false;
}

void
jspGetLeftArg(JsonPathItem *v, JsonPathItem *a)
{
	Assert(v->type == jpiAnd ||
		   v->type == jpiOr ||
		   v->type == jpiEqual ||
		   v->type == jpiNotEqual ||
		   v->type == jpiLess ||
		   v->type == jpiGreater ||
		   v->type == jpiLessOrEqual ||
		   v->type == jpiGreaterOrEqual ||
		   v->type == jpiAdd ||
		   v->type == jpiSub ||
		   v->type == jpiMul ||
		   v->type == jpiDiv ||
		   v->type == jpiMod ||
		   v->type == jpiStartsWith);

	jspInitByBuffer(a, v->base, v->content.args.left);
}

void
jspGetRightArg(JsonPathItem *v, JsonPathItem *a)
{
	Assert(v->type == jpiAnd ||
		   v->type == jpiOr ||
		   v->type == jpiEqual ||
		   v->type == jpiNotEqual ||
		   v->type == jpiLess ||
		   v->type == jpiGreater ||
		   v->type == jpiLessOrEqual ||
		   v->type == jpiGreaterOrEqual ||
		   v->type == jpiAdd ||
		   v->type == jpiSub ||
		   v->type == jpiMul ||
		   v->type == jpiDiv ||
		   v->type == jpiMod ||
		   v->type == jpiStartsWith);

	jspInitByBuffer(a, v->base, v->content.args.right);
}

bool
jspGetBool(JsonPathItem *v)
{
	Assert(v->type == jpiBool);

	return (bool) *v->content.value.data;
}

Numeric
jspGetNumeric(JsonPathItem *v)
{
	Assert(v->type == jpiNumeric);

	return (Numeric) v->content.value.data;
}

char *
jspGetString(JsonPathItem *v, int32 *len)
{
	Assert(v->type == jpiKey ||
		   v->type == jpiString ||
		   v->type == jpiVariable);

	if (len)
		*len = v->content.value.datalen;
	return v->content.value.data;
}

bool
jspGetArraySubscript(JsonPathItem *v, JsonPathItem *from, JsonPathItem *to,
					 int i)
{
	Assert(v->type == jpiIndexArray);

	jspInitByBuffer(from, v->base, v->content.array.elems[i].from);

	if (!v->content.array.elems[i].to)
		return false;

	jspInitByBuffer(to, v->base, v->content.array.elems[i].to);

	return true;
}

static inline JsonPathParseItem *
jspInitParseItem(JsonPathParseItem *item, JsonPathItemType type,
				 JsonPathParseItem *next)
{
	if (!item)
		item = palloc(sizeof(*item));

	item->type = type;
	item->next = next;

	return item;
}

static JsonPathParseItem *
jspInitParseItemJsonbScalar(JsonPathParseItem *item, JsonbValue	*jbv)
{
	/* jbv and jpi scalar types have the same values */
	item = jspInitParseItem(item, (JsonPathItemType) jbv->type, NULL);

	switch (jbv->type)
	{
		case jbvNull:
			break;

		case jbvBool:
			item->value.boolean = jbv->val.boolean;
			break;

		case jbvString:
			item->value.string.val = jbv->val.string.val;
			item->value.string.len = jbv->val.string.len;
			break;

		case jbvNumeric:
			item->value.numeric = jbv->val.numeric;
			break;

		default:
			elog(ERROR, "invalid scalar jsonb value type: %d", jbv->type);
			break;
	}

	return item;
}

static bool
replaceVariableReference(JsonPathContext *cxt, JsonPathItem *var, int32 pos)
{
	JsonbValue	name;
	JsonbValue *value;
	JsonPathParseItem tmp;
	JsonPathParseItem *item;

	name.type = jbvString;
	name.val.string.val = jspGetString(var, &name.val.string.len);

	value = findJsonbValueFromContainer(&cxt->vars->root, JB_FOBJECT, &name);

	if (!value)
		return false;

	cxt->buf->len = pos + JSONPATH_HDRSZ;	/* reset buffer */

	if (!IsAJsonbScalar(value))
	{
		cxt->varsCantBeSubstituted = true;
		return false;
	}

	item = jspInitParseItemJsonbScalar(&tmp, value);

	flattenJsonPathParseItem(cxt, item, false, false);

	return true;
}

static JsonPath *
substituteVariables(JsonPath *jsp, Jsonb *vars)
{
	JsonPathParseItem item;

	jspInitParseItem(&item, jpiBinary, NULL);
	item.value.binary = jsp;

	return encodeJsonPath(&item, !!(jsp->header & JSONPATH_LAX),
						  VARSIZE(jsp) + VARSIZE(vars), vars);
}

static Const *
getConstExpr(Expr *expr, Oid typid)
{
	if (!IsA(expr, Const) ||
		((Const *) expr)->constisnull ||
		((Const *) expr)->consttype != typid)
		return NULL;

	return (Const *) expr;
}

/* Planner support for jsonb_path_match() and jsonb_path_exists() */
static Node *
jsonb_path_support(Node *rawreq, bool exists)
{
	Node       *ret = NULL;

	if (IsA(rawreq, SupportRequestIndexCondition))
	{
		/* Try to convert operator/function call to index conditions */
		SupportRequestIndexCondition *req = (SupportRequestIndexCondition *) rawreq;

		/*
		 * Currently we have no "reverse" match operators with the pattern on
		 * the left, so we only need consider cases with the indexkey on the
		 * left.
		 */
		if (req->indexarg != 0)
			return NULL;

		if (is_funcclause(req->node))
		{
			FuncExpr   *clause = (FuncExpr *) req->node;
			Expr	   *opexpr;
			Expr	   *jspexpr;
			Expr	   *jsonexpr;
			Const	   *pathexpr;
			Const	   *varsexpr;
			Const	   *silentexpr;
			Jsonb	   *vars;
			Oid			oproid;

			if (list_length(clause->args) < 4)
				return NULL;

			if (!(pathexpr = getConstExpr(lsecond(clause->args), JSONPATHOID)))
				return NULL;

			if (!(silentexpr = getConstExpr(lfourth(clause->args), BOOLOID)) ||
				!DatumGetBool(silentexpr->constvalue))
				return NULL;

			if ((varsexpr = getConstExpr(lthird(clause->args), JSONBOID)))
			{
				vars = DatumGetJsonbP(varsexpr->constvalue);

				if (!JsonContainerIsObject(&vars->root))
					return NULL;

				if (JsonContainerSize(&vars->root) <= 0)
					jspexpr = (Expr *) pathexpr;
				else
				{
					JsonPath   *jsp = DatumGetJsonPathP(pathexpr->constvalue);

					jsp = substituteVariables(jsp, vars);

					if (!jsp)
						return NULL;

					jspexpr = (Expr *) makeConst(JSONPATHOID, -1, InvalidOid,
												 -1, PointerGetDatum(jsp),
												 false, false);
				}
			}
			else
			{
				List	   *args = list_make2(pathexpr, lthird(clause->args));

				jspexpr = (Expr *) makeFuncExpr(F_JSONPATH_EMBED_VARS,
												JSONPATHOID, args,
												InvalidOid, InvalidOid,
												COERCE_EXPLICIT_CALL);
			}

			jsonexpr = linitial(clause->args);

			oproid = exists ? JsonbPathExistsOperator : JsonbPathMatchOperator;
			opexpr = make_opclause(oproid, BOOLOID, false,
								   jsonexpr, jspexpr,
								   InvalidOid, req->indexcollation);

			req->lossy = false;

			return (Node *) list_make1(opexpr);
		}
	}

	return ret;
}

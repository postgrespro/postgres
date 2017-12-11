/*-------------------------------------------------------------------------
 *
 * ts_configmap.c
 *		internal represtation of text search configuration and utilities for it
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/tsearch/ts_confimap.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>

#include "access/heapam.h"
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/pg_ts_dict.h"
#include "tsearch/ts_cache.h"
#include "tsearch/ts_configmap.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"

/* Size selected based on assumption that 1024 frames of stack is enouth for parsing of any configuration */
#define JSONB_PARSE_STATE_STACK_SIZE 1024

/*
 * Used during the parsing of TSMapElement from JSONB into internal
 * datastructures.
 */
typedef enum TSMapParseState {
	TSMPS_WAIT_ELEMENT,
	TSMPS_READ_DICT_OID,
	TSMPS_READ_COMPLEX_OBJ,
	TSMPS_READ_EXPRESSION,
	TSMPS_READ_CASE,
	TSMPS_READ_OPERATOR,
	TSMPS_READ_COMMAND,
	TSMPS_READ_CONDITION,
	TSMPS_READ_ELSEBRANCH,
	TSMPS_READ_MATCH,
	TSMPS_READ_KEEP,
	TSMPS_READ_LEFT,
	TSMPS_READ_RIGHT
} TSMapParseState;

typedef struct TSMapJsonbParseData {
	TSMapParseState states[JSONB_PARSE_STATE_STACK_SIZE];
	int statesIndex;
	TSMapElement *element;
} TSMapJsonbParseData;

static JsonbValue *TSMapElementToJsonbValue(TSMapElement *element, JsonbParseState *jsonbState);
static TSMapElement *JsonbToTSMapElement(JsonbContainer *root);

static void
TSMapPrintDictName(Oid dictId, StringInfo result)
{
	Relation	maprel;
	Relation	mapidx;
	ScanKeyData mapskey;
	SysScanDesc mapscan;
	HeapTuple	maptup;
	Form_pg_ts_dict dict;

	maprel = heap_open(TSDictionaryRelationId, AccessShareLock);
	mapidx = index_open(TSDictionaryOidIndexId, AccessShareLock);

	ScanKeyInit(&mapskey, ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(dictId));
	mapscan = systable_beginscan_ordered(maprel, mapidx,
										 NULL, 1, &mapskey);

	maptup = systable_getnext_ordered(mapscan, ForwardScanDirection);
	dict = (Form_pg_ts_dict) GETSTRUCT(maptup);
	appendStringInfoString(result, dict->dictname.data);

	systable_endscan_ordered(mapscan);
	index_close(mapidx, AccessShareLock);
	heap_close(maprel, AccessShareLock);
}

static void
TSMapPrintExpression(TSMapExpression *expression, StringInfo result)
{

	if (expression->left)
		TSMapPrintElement(expression->left, result);

	switch (expression->operator)
	{
		case TSMAP_OP_UNION:
			appendStringInfoString(result, " UNION ");
			break;
		case TSMAP_OP_EXCEPT:
			appendStringInfoString(result, " EXCEPT ");
			break;
		case TSMAP_OP_INTERSECT:
			appendStringInfoString(result, " INTERSECT ");
			break;
		case TSMAP_OP_MAP:
			appendStringInfoString(result, " MAP ");
			break;
		case TSMAP_OP_MAPBY:
			appendStringInfoString(result, " MAP ");
			break;
		default:
			appendStringInfo(result, " %d ", expression->operator);
			break;
	}

	if (expression->right)
		TSMapPrintElement(expression->right, result);
}

static void
TSMapPrintCase(TSMapCase *caseObject, StringInfo result)
{
	appendStringInfoString(result, " CASE ");

	TSMapPrintElement(caseObject->condition, result);

	appendStringInfoString(result, "\nWHEN ");
	if (!caseObject->match)
		appendStringInfoString(result, "NO ");
	appendStringInfoString(result, "MATCH THEN ");

	TSMapPrintElement(caseObject->command, result);

	if (caseObject->elsebranch != NULL)
	{
		appendStringInfoString(result, "\nELSE ");
		TSMapPrintElement(caseObject->elsebranch, result);
	}
	appendStringInfoString(result, " END");
}

void
TSMapPrintElement(TSMapElement *element, StringInfo result)
{
	switch (element->type)
	{
		case TSMAP_EXPRESSION:
			TSMapPrintExpression((TSMapExpression *)element->object, result);
			break;
		case TSMAP_DICTIONARY:
			TSMapPrintDictName(*(Oid *)element->object, result);
			break;
		case TSMAP_CASE:
			TSMapPrintCase((TSMapCase *)element->object, result);
			break;
		case TSMAP_KEEP:
			appendStringInfoString(result, " SELECT ");
			break;
	}
}

Datum
dictionary_mapping_to_text(PG_FUNCTION_ARGS)
{
	Oid			cfgOid = PG_GETARG_OID(0);
	int32		tokentype = PG_GETARG_INT32(1);
	StringInfo	rawResult;
	text	   *result = NULL;
	TSConfigCacheEntry *cacheEntry;

	cacheEntry = lookup_ts_config_cache(cfgOid);
	rawResult = makeStringInfo();
	initStringInfo(rawResult);

	if (cacheEntry->lenmap > tokentype && cacheEntry->map[tokentype] != NULL)
	{
		TSMapElement *element = cacheEntry->map[tokentype];
		TSMapPrintElement(element, rawResult);
	}

	result = cstring_to_text(rawResult->data);
	pfree(rawResult);
	PG_RETURN_TEXT_P(result);
}

static JsonbValue *
IntToJsonbValue(int intValue)
{
	char		buffer[16];
	JsonbValue *value = palloc0(sizeof(JsonbValue));

	memset(buffer, 0, sizeof(char) * 16);

	pg_ltoa(intValue, buffer);
	value->type = jbvNumeric;
	value->val.numeric = DatumGetNumeric(DirectFunctionCall3(
															 numeric_in,
															 CStringGetDatum(buffer),
															 ObjectIdGetDatum(InvalidOid),
															 Int32GetDatum(-1)
															 ));
	return value;
}

static JsonbValue *
TSMapExpressionToJsonbValue(TSMapExpression *expression, JsonbParseState *jsonbState)
{
	JsonbValue	key;
	JsonbValue *value = NULL;

	if (expression == NULL)
		return NULL;

	pushJsonbValue(&jsonbState, WJB_BEGIN_OBJECT, NULL);

	key.type = jbvString;
	key.val.string.len = strlen("operator");
	key.val.string.val = "operator";
	value = IntToJsonbValue(expression->operator);

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	pushJsonbValue(&jsonbState, WJB_VALUE, value);

	key.type = jbvString;
	key.val.string.len = strlen("left");
	key.val.string.val = "left";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(expression->left, jsonbState);
	if (value && IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	key.type = jbvString;
	key.val.string.len = strlen("right");
	key.val.string.val = "right";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(expression->right, jsonbState);
	if (value && IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	return pushJsonbValue(&jsonbState, WJB_END_OBJECT, NULL);
}

static JsonbValue *
TSMapCaseToJsonbValue(TSMapCase *caseObject, JsonbParseState *jsonbState)
{
	JsonbValue	key;
	JsonbValue *value = NULL;

	pushJsonbValue(&jsonbState, WJB_BEGIN_OBJECT, NULL);

	key.type = jbvString;
	key.val.string.len = strlen("condition");
	key.val.string.val = "condition";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(caseObject->condition, jsonbState);

	if (IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	key.type = jbvString;
	key.val.string.len = strlen("command");
	key.val.string.val = "command";

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	value = TSMapElementToJsonbValue(caseObject->command, jsonbState);

	if (IsAJsonbScalar(value))
		pushJsonbValue(&jsonbState, WJB_VALUE, value);

	if (caseObject->elsebranch != NULL)
	{
		key.type = jbvString;
		key.val.string.len = strlen("elsebranch");
		key.val.string.val = "elsebranch";

		pushJsonbValue(&jsonbState, WJB_KEY, &key);
		value = TSMapElementToJsonbValue(caseObject->elsebranch, jsonbState);

		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonbState, WJB_VALUE, value);
	}

	key.type = jbvString;
	key.val.string.len = strlen("match");
	key.val.string.val = "match";

	value = IntToJsonbValue(caseObject->match ? 1 : 0);

	pushJsonbValue(&jsonbState, WJB_KEY, &key);
	pushJsonbValue(&jsonbState, WJB_VALUE, value);

	return pushJsonbValue(&jsonbState, WJB_END_OBJECT, NULL);
}

static JsonbValue *
TSMapKeepToJsonbValue(JsonbParseState *jsonbState)
{
	JsonbValue *value = palloc0(sizeof(JsonbValue));

	value->type = jbvString;
	value->val.string.len = strlen("keep");
	value->val.string.val = "keep";

	return pushJsonbValue(&jsonbState, WJB_VALUE, value);
}

JsonbValue *
TSMapElementToJsonbValue(TSMapElement *element, JsonbParseState *jsonbState)
{
	JsonbValue *result = NULL;
	if (element != NULL)
	{
		switch (element->type)
		{
			case TSMAP_EXPRESSION:
				result = TSMapExpressionToJsonbValue((TSMapExpression *)element->object, jsonbState);
				break;
			case TSMAP_DICTIONARY:
				result = IntToJsonbValue(*(Oid *)element->object);
				break;
			case TSMAP_CASE:
				result = TSMapCaseToJsonbValue((TSMapCase *)element->object, jsonbState);
				break;
			case TSMAP_KEEP:
				Assert(element->parent->type == TSMAP_CASE);
				result = TSMapElementToJsonbValue(((TSMapCase*)element->parent->object)->condition, jsonbState);
				// result = TSMapKeepToJsonbValue(jsonbState);
				break;
		}
	}
	return result;
}

Jsonb *
TSMapToJsonb(TSMapElement *element)
{
	JsonbParseState *jsonbState = NULL;
	JsonbValue *out;
	Jsonb	   *result;

	out = TSMapElementToJsonbValue(element, jsonbState);

	result = JsonbValueToJsonb(out);
	return result;
}

/* -------------------------------------------------------------------------- */

static bool
JsonbValueIsTSMapCaseKey(JsonbValue *value)
{
	/*
	 * JsonbValue string may be not null-terminated.
	 * Convert it for apropriate behavior of strcmp function.
	 */
	char *key = palloc0(sizeof(char) * (value->val.string.len + 1));
	key[value->val.string.len] = '\0';
	memcpy(key, value->val.string.val, sizeof(char) * value->val.string.len);
	// parseData->statesIndex++;
	if (strcmp(key, "match") == 0 || strcmp(key, "condition") == 0 || strcmp(key, "command") == 0 || strcmp(key, "elsebranch") == 0)
		return true;
	return false;
}

static bool
JsonbValueIsTSMapExpressionKey(JsonbValue *value)
{
	/*
	 * JsonbValue string may be not null-terminated.
	 * Convert it for apropriate behavior of strcmp function.
	 */
	char *key = palloc0(sizeof(char) * (value->val.string.len + 1));
	key[value->val.string.len] = '\0';
	memcpy(key, value->val.string.val, sizeof(char) * value->val.string.len);
	// parseData->statesIndex++;
	if (strcmp(key, "operator") == 0 || strcmp(key, "left") == 0 || strcmp(key, "right") == 0)
		return true;
	return false;
}

/*
 * Configure parseData->element according to value (key)
 */
static void
JsonbBeginObjectKey(JsonbValue value, TSMapJsonbParseData *parseData)
{
	TSMapElement *parentElement = parseData->element;
	parseData->element = palloc0(sizeof(TSMapElement));
	parseData->element->parent = parentElement;

	/* Overwrite object-type state based on key */
	if (JsonbValueIsTSMapExpressionKey(&value))
	{
		parseData->states[parseData->statesIndex] = TSMPS_READ_EXPRESSION;
		parseData->element->type = TSMAP_EXPRESSION;
		parseData->element->object = palloc0(sizeof(TSMapExpression));
	}
	else if (JsonbValueIsTSMapCaseKey(&value))
	{
		parseData->states[parseData->statesIndex] = TSMPS_READ_CASE;
		parseData->element->type = TSMAP_CASE;
		parseData->element->object = palloc0(sizeof(TSMapCase));
	}
}

static void
JsonbKeyExpressionProcessing(JsonbValue value, TSMapJsonbParseData *parseData)
{
	/*
	 * JsonbValue string may be not null-terminated.
	 * Convert it for apropriate behavior of strcmp function.
	 */
	char *key = palloc0(sizeof(char) * (value.val.string.len + 1));
	memcpy(key, value.val.string.val, sizeof(char) * value.val.string.len);
	parseData->statesIndex++;
	if (strcmp(key, "operator") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_OPERATOR;
	else if (strcmp(key, "left") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_LEFT;
	else if (strcmp(key, "right") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_RIGHT;
	else
		// TODO: Error
		Assert(false);
}

static void
JsonbKeyCaseProcessing(JsonbValue value, TSMapJsonbParseData *parseData)
{
	/*
	 * JsonbValue string may be not null-terminated.
	 * Convert it for apropriate behavior of strcmp function.
	 */
	char *key = palloc0(sizeof(char) * (value.val.string.len + 1));
	memcpy(key, value.val.string.val, sizeof(char) * value.val.string.len);
	parseData->statesIndex++;
	if (strcmp(key, "condition") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_CONDITION;
	else if (strcmp(key, "command") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_COMMAND;
	else if (strcmp(key, "elsebranch") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_ELSEBRANCH;
	else if (strcmp(key, "match") == 0)
		parseData->states[parseData->statesIndex] = TSMPS_READ_MATCH;
	else
		// TODO: Error
		Assert(false);
}

static int
JsonbValueToInt(JsonbValue *value)
{
	char *str;
	str = DatumGetCString(DirectFunctionCall1(numeric_out, NumericGetDatum(value->val.numeric)));
	return pg_atoi(str, sizeof(int), 0);
}

static TSMapElement *
JsonbReadOid(JsonbValue *value, TSMapElement *parent)
{
	TSMapElement *element = palloc0(sizeof(TSMapElement));
	element->parent = parent;
	element->type = TSMAP_DICTIONARY;
	element->object = palloc0(sizeof(Oid));
	*((Oid*)element->object) = JsonbValueToInt(value);
	return element;
}

static TSMapElement *
JsonbReadString(JsonbValue *value, TSMapElement *parent)
{
	char *str;
	TSMapElement *element = palloc0(sizeof(TSMapElement));
	element->parent = parent;
	str = palloc0(sizeof(char) * (value->val.string.len + 1));
	memcpy(str, value->val.string.val, sizeof(char) * value->val.string.len);
	if (strcmp(str, "KEEP") == 0)
	{
		element->type = TSMAP_KEEP;
	}
	pfree(str);
	return element;
}

static void
JsonbProcessElement(JsonbIteratorToken r, JsonbValue value, TSMapJsonbParseData *parseData)
{
	TSMapElement *element;
	switch (r)
	{
		case WJB_KEY:
			if (parseData->states[parseData->statesIndex] == TSMPS_READ_COMPLEX_OBJ)
				JsonbBeginObjectKey(value, parseData);

			if (parseData->states[parseData->statesIndex] == TSMPS_READ_EXPRESSION)
				JsonbKeyExpressionProcessing(value, parseData);
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_CASE)
				JsonbKeyCaseProcessing(value, parseData);

			break;
		case WJB_BEGIN_OBJECT:
			parseData->statesIndex++;
			parseData->states[parseData->statesIndex] = TSMPS_READ_COMPLEX_OBJ;
			break;
		case WJB_END_OBJECT:
			if (parseData->states[parseData->statesIndex] == TSMPS_READ_LEFT)
				((TSMapExpression*)parseData->element->parent->object)->left = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_RIGHT)
				((TSMapExpression*)parseData->element->parent->object)->right = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_CONDITION)
				((TSMapCase*)parseData->element->parent->object)->condition = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_COMMAND)
				((TSMapCase*)parseData->element->parent->object)->command = parseData->element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_ELSEBRANCH)
				((TSMapCase*)parseData->element->parent->object)->elsebranch = parseData->element;

			parseData->statesIndex--;
			Assert(parseData->statesIndex >= 0);
			if (parseData->element->parent != NULL)
				parseData->element = parseData->element->parent;
			break;
		case WJB_VALUE:
			if (value.type == jbvBinary)
				element = JsonbToTSMapElement(value.val.binary.data);
			else if (value.type == jbvString)
				element = JsonbReadString(&value, parseData->element);
			else if (value.type == jbvNumeric)
				element = JsonbReadOid(&value, parseData->element);

			if (parseData->states[parseData->statesIndex] == TSMPS_READ_CONDITION)
				((TSMapCase*)parseData->element->object)->condition = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_COMMAND)
				((TSMapCase*)parseData->element->object)->command = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_ELSEBRANCH)
				((TSMapCase*)parseData->element->object)->elsebranch = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_MATCH)
				((TSMapCase*)parseData->element->object)->match = JsonbValueToInt(&value) == 1 ? true : false;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_OPERATOR)
				((TSMapExpression*)parseData->element->object)->operator = JsonbValueToInt(&value);
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_LEFT)
				((TSMapExpression*)parseData->element->object)->left = element;
			else if (parseData->states[parseData->statesIndex] == TSMPS_READ_RIGHT)
				((TSMapExpression*)parseData->element->object)->right = element;

			parseData->statesIndex--;
			Assert(parseData->statesIndex >= 0);
			if (parseData->element->parent != NULL)
				parseData->element = parseData->element->parent;
			break;
		case WJB_ELEM:
			if (parseData->states[parseData->statesIndex] == TSMPS_WAIT_ELEMENT)
			{
				if (parseData->element != NULL)
					parseData->element = JsonbReadOid(&value, parseData->element->parent);
				else
					parseData->element = JsonbReadOid(&value, NULL);
			}
			break;
		case WJB_BEGIN_ARRAY:
		case WJB_END_ARRAY:
		default:
			break;
	}
}

static TSMapElement *
JsonbToTSMapElement(JsonbContainer *root)
{
	TSMapJsonbParseData parseData;
	JsonbIteratorToken r;
	JsonbIterator *it;
	JsonbValue	val;

	parseData.statesIndex = 0;
	parseData.states[parseData.statesIndex] = TSMPS_WAIT_ELEMENT;
	parseData.element = NULL;

	it = JsonbIteratorInit(root);
	while ((r = JsonbIteratorNext(&it, &val, true)) != WJB_DONE)
	{
		JsonbProcessElement(r, val, &parseData);
	}

	return parseData.element;
}

TSMapElement *
JsonbToTSMap(Jsonb *json)
{
	JsonbContainer *root = &json->root;
	return JsonbToTSMapElement(root);
}

/*
 * Text Search Configuration Map Utils
 */

typedef struct OidList {
	Oid* data;
	int size; /* Size of data array. Uninitialized elemenets in data filled with InvalidOid */
} OidList;

static OidList *
OidListInit()
{
	OidList *result = palloc0(sizeof(OidList));
	result->size = 1;
	result->data = palloc0(result->size * sizeof(Oid));
	result->data[0] = InvalidOid;
	return result;
}

static void
OidListAdd(OidList *list, Oid oid)
{
	int i;
	for (i = 0; list->data[i] != InvalidOid; i++)
		if (list->data[i] == oid)
			return;

	i++;
	if (i == list->size)
	{
		int j;
		list->size = list->size * 2;
		list->data = repalloc(list->data, sizeof(Oid) * list->size);

		for (j = i; j < list->size; j++)
			list->data[j] = InvalidOid;
	}
	list->data[i] = oid;
}

static void
TSMapGetDictionariesInternal(TSMapElement *config, OidList *list)
{
	if (config != NULL)
	{
		switch (config->type)
		{
			case TSMAP_EXPRESSION:
				TSMapGetDictionariesInternal(((TSMapExpression*)config->object)->left, list);
				TSMapGetDictionariesInternal(((TSMapExpression*)config->object)->right, list);
				break;
			case TSMAP_CASE:
				TSMapGetDictionariesInternal(((TSMapCase*)config->object)->command, list);
				TSMapGetDictionariesInternal(((TSMapCase*)config->object)->condition, list);
				TSMapGetDictionariesInternal(((TSMapCase*)config->object)->elsebranch, list);
				break;
			case TSMAP_DICTIONARY:
				OidListAdd(list, *(Oid*)config->object);
				break;
		}
	}
}

Oid *
TSMapGetDictionaries(TSMapElement *config)
{
	Oid *result;
	OidList *list = OidListInit();

	TSMapGetDictionariesInternal(config, list);

	result = list->data;
	pfree(list);

	return result;
}

void
TSMapReplaceDictionary(TSMapElement *config, Oid oldDict, Oid newDict)
{
	if (config != NULL)
	{
		switch (config->type)
		{
			case TSMAP_EXPRESSION:
				TSMapReplaceDictionary(((TSMapExpression*)config->object)->left, oldDict, newDict);
				TSMapReplaceDictionary(((TSMapExpression*)config->object)->right, oldDict, newDict);
				break;
			case TSMAP_CASE:
				TSMapReplaceDictionary(((TSMapCase*)config->object)->command, oldDict, newDict);
				TSMapReplaceDictionary(((TSMapCase*)config->object)->condition, oldDict, newDict);
				TSMapReplaceDictionary(((TSMapCase*)config->object)->elsebranch, oldDict, newDict);
				break;
			case TSMAP_DICTIONARY:
				if (*(Oid*)config->object == oldDict)
					*(Oid*)config->object = newDict;
				break;
		}
	}
}

/*
 * Text Search Configuration Map Memory Management
 */

static TSMapElement *
TSMapExpressionMoveToMemoryContext(TSMapExpression *expression, MemoryContext context)
{
	TSMapElement *result = MemoryContextAlloc(context, sizeof(TSMapElement));
	TSMapExpression *resultExpression = MemoryContextAlloc(context, sizeof(TSMapExpression));

	memset(resultExpression, 0, sizeof(TSMapExpression));
	result->object = resultExpression;
	result->type = TSMAP_EXPRESSION;

	resultExpression->operator = expression->operator;

	if (expression->left)
	{
		resultExpression->left = TSMapMoveToMemoryContext(expression->left, context);
		resultExpression->left->parent = result;
	}

	if (expression->right)
	{
		resultExpression->right = TSMapMoveToMemoryContext(expression->right, context);
		resultExpression->right->parent = result;
	}

	return result;
}

static TSMapElement *
TSMapCaseMoveToMemoryContext(TSMapCase *caseObject, MemoryContext context)
{
	TSMapElement *result = MemoryContextAlloc(context, sizeof(TSMapElement));
	TSMapCase *resultCaseObject = MemoryContextAlloc(context, sizeof(TSMapCase));

	memset(resultCaseObject, 0, sizeof(TSMapCase));
	result->object = resultCaseObject;
	result->type = TSMAP_CASE;

	resultCaseObject->match = caseObject->match;

	if (caseObject->command)
	{
		resultCaseObject->command = TSMapMoveToMemoryContext(caseObject->command, context);
		resultCaseObject->command->parent = result;
	}
	if (caseObject->condition)
	{
		resultCaseObject->condition = TSMapMoveToMemoryContext(caseObject->condition, context);
		resultCaseObject->condition->parent = result;
	}
	if (caseObject->elsebranch)
	{
		resultCaseObject->elsebranch = TSMapMoveToMemoryContext(caseObject->elsebranch, context);
		resultCaseObject->elsebranch->parent = result;
	}

	return result;
}

TSMapElement *
TSMapMoveToMemoryContext(TSMapElement *config, MemoryContext context)
{
	TSMapElement *result;

	switch (config->type)
	{
		case TSMAP_EXPRESSION:
			result = TSMapExpressionMoveToMemoryContext((TSMapExpression*)config->object, context);
			break;
		case TSMAP_CASE:
			result = TSMapCaseMoveToMemoryContext((TSMapCase*)config->object, context);
			break;
		case TSMAP_DICTIONARY:
			result = MemoryContextAlloc(context, sizeof(TSMapElement));
			result->type = TSMAP_DICTIONARY;
			result->object = MemoryContextAlloc(context, sizeof(Oid));
			*(Oid*)result->object = *(Oid*)config->object;
			break;
	}

	return result;
}

static void
TSMapExpressionFree(TSMapExpression *expression)
{
	if (expression->left)
		TSMapElementFree(expression->left);
	if (expression->right)
		TSMapElementFree(expression->right);
	pfree(expression);
}

static void
TSMapCaseFree(TSMapCase *caseObject)
{
	TSMapElementFree(caseObject->condition);
	TSMapElementFree(caseObject->command);
	TSMapElementFree(caseObject->elsebranch);
	pfree(caseObject);
}

void
TSMapElementFree(TSMapElement *element)
{
	if (element != NULL)
	{
		switch (element->type)
		{
			case TSMAP_CASE:
				TSMapCaseFree(element->object);
				break;
			case TSMAP_EXPRESSION:
				TSMapExpressionFree(element->object);
				break;
		}
		pfree(element);
	}
}

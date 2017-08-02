/*-------------------------------------------------------------------------
 *
 * ts_utils.c
 *		various support functions
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/tsearch/ts_utils.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>

#include "miscadmin.h"
#include "tsearch/ts_locale.h"
#include "tsearch/ts_utils.h"
#include "catalog/indexing.h"
#include "catalog/pg_ts_config_map.h"
#include "catalog/pg_ts_dict.h"
#include "storage/lockdefs.h"
#include "access/heapam.h"
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "utils/fmgroids.h"
#include "utils/builtins.h"
#include "tsearch/ts_cache.h"

/*
 * Used during the parsing of TSMapRuleList from JSONB into internal
 * datastructures.
 */
typedef enum TSMapRuleParseState {
	TSMRPS_BEGINING,
	TSMRPS_IN_CASES_ARRAY,
	TSMRPS_IN_CASE,
	TSMRPS_IN_CONDITION,
	TSMRPS_IN_COMMAND,
	TSMRPS_IN_EXPRESSION
} TSMapRuleParseState;

typedef enum TSMapRuleParseNodeType {
	TSMRPT_UNKNOWN,
	TSMRPT_NUMERIC,
	TSMRPT_EXPRESSION,
	TSMRPT_RULE_LIST,
	TSMRPT_RULE,
	TSMRPT_COMMAND,
	TSMRPT_CONDITION,
	TSMRPT_BOOL
} TSMapRuleParseNodeType;

typedef struct TSMapParseNode {
	TSMapRuleParseNodeType type;
	union {
		int					num_val;
		TSMapExpression	   *expression_val;
		TSMapRuleList	   *rule_list_val;
		TSMapRule		   *rule_val;
		TSMapCommand	   *command_val;
		TSMapCondition	   *condition_val;
		bool				bool_val;
	};
} TSMapParseNode;

static JsonbValue *
TSMapToJsonbValue(TSMapRuleList *rules, JsonbParseState *jsonb_state);
static TSMapParseNode *
JsonbToTSMapParse(JsonbContainer *root, TSMapRuleParseState *parse_state);

/*
 * Given the base name and extension of a tsearch config file, return
 * its full path name.  The base name is assumed to be user-supplied,
 * and is checked to prevent pathname attacks.  The extension is assumed
 * to be safe.
 *
 * The result is a palloc'd string.
 */
char *
get_tsearch_config_filename(const char *basename,
							const char *extension)
{
	char		sharepath[MAXPGPATH];
	char	   *result;

	/*
	 * We limit the basename to contain a-z, 0-9, and underscores.  This may
	 * be overly restrictive, but we don't want to allow access to anything
	 * outside the tsearch_data directory, so for instance '/' *must* be
	 * rejected, and on some platforms '\' and ':' are risky as well. Allowing
	 * uppercase might result in incompatible behavior between case-sensitive
	 * and case-insensitive filesystems, and non-ASCII characters create other
	 * interesting risks, so on the whole a tight policy seems best.
	 */
	if (strspn(basename, "abcdefghijklmnopqrstuvwxyz0123456789_") != strlen(basename))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid text search configuration file name \"%s\"",
						basename)));

	get_share_path(my_exec_path, sharepath);
	result = palloc(MAXPGPATH);
	snprintf(result, MAXPGPATH, "%s/tsearch_data/%s.%s",
			 sharepath, basename, extension);

	return result;
}

/*
 * Reads a stop-word file. Each word is run through 'wordop'
 * function, if given.  wordop may either modify the input in-place,
 * or palloc a new version.
 */
void
readstoplist(const char *fname, StopList *s, char *(*wordop) (const char *))
{
	char	  **stop = NULL;

	s->len = 0;
	if (fname && *fname)
	{
		char	   *filename = get_tsearch_config_filename(fname, "stop");
		tsearch_readline_state trst;
		char	   *line;
		int			reallen = 0;

		if (!tsearch_readline_begin(&trst, filename))
			ereport(ERROR,
					(errcode(ERRCODE_CONFIG_FILE_ERROR),
					 errmsg("could not open stop-word file \"%s\": %m",
							filename)));

		while ((line = tsearch_readline(&trst)) != NULL)
		{
			char	   *pbuf = line;

			/* Trim trailing space */
			while (*pbuf && !t_isspace(pbuf))
				pbuf += pg_mblen(pbuf);
			*pbuf = '\0';

			/* Skip empty lines */
			if (*line == '\0')
			{
				pfree(line);
				continue;
			}

			if (s->len >= reallen)
			{
				if (reallen == 0)
				{
					reallen = 64;
					stop = (char **) palloc(sizeof(char *) * reallen);
				}
				else
				{
					reallen *= 2;
					stop = (char **) repalloc((void *) stop,
											  sizeof(char *) * reallen);
				}
			}

			if (wordop)
			{
				stop[s->len] = wordop(line);
				if (stop[s->len] != line)
					pfree(line);
			}
			else
				stop[s->len] = line;

			(s->len)++;
		}

		tsearch_readline_end(&trst);
		pfree(filename);
	}

	s->stop = stop;

	/* Sort to allow binary searching */
	if (s->stop && s->len > 0)
		qsort(s->stop, s->len, sizeof(char *), pg_qsort_strcmp);
}

bool
searchstoplist(StopList *s, char *key)
{
	return (s->stop && s->len > 0 &&
			bsearch(&key, s->stop, s->len,
					sizeof(char *), pg_qsort_strcmp)) ? true : false;
}

Datum
dictionary_pipe_to_text(PG_FUNCTION_ARGS)
{
	PG_RETURN_NULL();
}

static JsonbValue *
TSIntToJsonbValue(int int_value)
{
	char			buffer[16];
	JsonbValue	   *value = palloc0(sizeof(JsonbValue));

	memset(buffer, 0, sizeof(char) * 16);

	pg_ltoa(int_value, buffer);
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
TSExpressionToJsonb(TSMapExpression *expression, JsonbParseState *jsonb_state)
{
	if (expression->dictionary != InvalidOid)
	{
		return TSIntToJsonbValue(expression->dictionary);
	}
	else if (expression->is_true)
	{
		JsonbValue *value = palloc0(sizeof(JsonbValue));
		value->type = jbvBool;
		value->val.boolean = true;
		return value;
	}
	else
	{
		JsonbValue		key;
		JsonbValue	   *value = NULL;

		pushJsonbValue(&jsonb_state, WJB_BEGIN_OBJECT, NULL);

		key.type = jbvString;
		key.val.string.len = strlen("operator");
		key.val.string.val = "operator";
		value = TSIntToJsonbValue(expression->operator);

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("left");
		key.val.string.val = "left";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		value = TSExpressionToJsonb(expression->left, jsonb_state);
		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("right");
		key.val.string.val = "right";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		value = TSExpressionToJsonb(expression->right, jsonb_state);
		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		return pushJsonbValue(&jsonb_state, WJB_END_OBJECT, NULL);
	}
}

static JsonbValue *
TSRuleToJsonbValue(TSMapRule *rule, JsonbParseState *jsonb_state)
{
	if (rule->dictionary != InvalidOid)
	{
		return TSIntToJsonbValue(rule->dictionary);
	}
	else
	{
		JsonbValue		key;
		JsonbValue	   *value = NULL;

		pushJsonbValue(&jsonb_state, WJB_BEGIN_OBJECT, NULL);

		key.type = jbvString;
		key.val.string.len = strlen("condition");
		key.val.string.val = "condition";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		value = TSExpressionToJsonb(rule->condition.expression, jsonb_state);

		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		key.type = jbvString;
		key.val.string.len = strlen("command");
		key.val.string.val = "command";

		pushJsonbValue(&jsonb_state, WJB_KEY, &key);
		if (rule->command.is_expression)
			value = TSExpressionToJsonb(rule->command.expression, jsonb_state);
		else
			value = TSMapToJsonbValue(rule->command.ruleList, jsonb_state);

		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_VALUE, value);

		return pushJsonbValue(&jsonb_state, WJB_END_OBJECT, NULL);
	}
}

static JsonbValue *
TSMapToJsonbValue(TSMapRuleList *rules, JsonbParseState *jsonb_state)
{
	JsonbValue	   *out;
	int				i;

	pushJsonbValue(&jsonb_state, WJB_BEGIN_ARRAY, NULL);
	for (i = 0; i < rules->count; i++)
	{
		JsonbValue *value = TSRuleToJsonbValue(&rules->data[i], jsonb_state);
		if (IsAJsonbScalar(value))
			pushJsonbValue(&jsonb_state, WJB_ELEM, value);
	}
	out = pushJsonbValue(&jsonb_state, WJB_END_ARRAY, NULL);
	return out;
}

Jsonb *
TSMapToJsonb(TSMapRuleList *rules)
{
	JsonbParseState *jsonb_state = NULL;
	JsonbValue	   *out;
	Jsonb		   *result;

	out = TSMapToJsonbValue(rules, jsonb_state);

	result = JsonbValueToJsonb(out);
	return result;
}

static inline TSMapExpression *
JsonbToTSMapGetExpression(TSMapParseNode *node)
{
	TSMapExpression *result;
	if (node->type == TSMRPT_NUMERIC)
	{
		result = palloc0(sizeof(TSMapExpression));
		result->dictionary = node->num_val;
	}
	else if (node->type == TSMRPT_BOOL)
	{
		result = palloc0(sizeof(TSMapExpression));
		result->is_true = node->bool_val;
	}
	else
		result = node->expression_val;

	pfree(node);

	return result;
}

static TSMapParseNode *
JsonbToTSMapParseObject(JsonbValue *value, TSMapRuleParseState *parse_state)
{
	TSMapParseNode	   *result = palloc0(sizeof(TSMapParseNode));
	char			   *str;
	switch (value->type)
	{
		case jbvNumeric:
			result->type = TSMRPT_NUMERIC;
			str = DatumGetCString(
					DirectFunctionCall1(numeric_out, NumericGetDatum(value->val.numeric)));
			result->num_val = pg_atoi(str, sizeof(result->num_val), 0);
			break;
		case jbvArray:
			Assert(*parse_state == TSMRPS_IN_COMMAND);
		case jbvBinary:
			result = JsonbToTSMapParse(value->val.binary.data, parse_state);
			break;
		case jbvBool:
			result->type = TSMRPT_BOOL;
			result->bool_val = value->val.boolean;
			break;
		case jbvObject:
		case jbvNull:
		case jbvString:
			break;
	}
	return result;
}

static TSMapParseNode *
JsonbToTSMapParse(JsonbContainer *root, TSMapRuleParseState *parse_state)
{
	JsonbIteratorToken r;
	JsonbValue		val;
	JsonbIterator  *it;
	TSMapParseNode *result;
	TSMapParseNode *nested_result;
	char		   *key;
	TSMapRuleList  *rule_list = NULL;

	it = JsonbIteratorInit(root);
	result = palloc0(sizeof(TSMapParseNode));
	result->type = TSMRPT_UNKNOWN;
	while ((r = JsonbIteratorNext(&it, &val, true)) != WJB_DONE)
	{
		switch (r)
		{
			case WJB_BEGIN_ARRAY:
				if (*parse_state == TSMRPS_BEGINING || *parse_state == TSMRPS_IN_EXPRESSION)
				{
					*parse_state = TSMRPS_IN_CASES_ARRAY;
					rule_list = palloc0(sizeof(TSMapRuleList));
				}
				break;
			case WJB_KEY:
				key = palloc0(sizeof(char) * (val.val.string.len + 1));
				memcpy(key, val.val.string.val, sizeof(char) * val.val.string.len);

				r = JsonbIteratorNext(&it, &val, true);
				if (*parse_state == TSMRPS_IN_CASE)
				{
					if (strcmp(key, "command") == 0)
						*parse_state = TSMRPS_IN_EXPRESSION;
					else if (strcmp(key, "condition") == 0)
						*parse_state = TSMRPS_IN_EXPRESSION;
				}

				nested_result = JsonbToTSMapParseObject(&val, parse_state);

				if (result->type == TSMRPT_RULE)
				{
					if (strcmp(key, "command") == 0)
					{
						result->rule_val->command.is_expression = nested_result->type == TSMRPT_EXPRESSION ||
															nested_result->type == TSMRPT_NUMERIC;

						if (result->rule_val->command.is_expression)
							result->rule_val->command.expression = JsonbToTSMapGetExpression(nested_result);
						else
							result->rule_val->command.ruleList = nested_result->rule_list_val;
					}
					else if (strcmp(key, "condition") == 0)
					{
						result->rule_val->condition.expression = JsonbToTSMapGetExpression(nested_result);
					}
					*parse_state = TSMRPS_IN_CASE;
				}
				else if (result->type == TSMRPT_COMMAND)
				{
					result->command_val->is_expression = nested_result->type == TSMRPT_EXPRESSION;
					if (result->command_val->is_expression)
						result->command_val->expression = JsonbToTSMapGetExpression(nested_result);
					else
						result->command_val->ruleList = nested_result->rule_list_val;
					*parse_state = TSMRPS_IN_COMMAND;
				}
				else if (result->type == TSMRPT_CONDITION)
				{
					result->condition_val->expression = JsonbToTSMapGetExpression(nested_result);
					*parse_state = TSMRPS_IN_COMMAND;
				}
				else if (result->type == TSMRPT_EXPRESSION)
				{
					if (strcmp(key, "left") == 0)
						result->expression_val->left = JsonbToTSMapGetExpression(nested_result);
					else if (strcmp(key, "right") == 0)
						result->expression_val->right = JsonbToTSMapGetExpression(nested_result);
					else if (strcmp(key, "operator") == 0)
						result->expression_val->operator = nested_result->num_val;
				}

				break;
			case WJB_BEGIN_OBJECT:
				if (*parse_state == TSMRPS_IN_CASES_ARRAY)
				{
					*parse_state = TSMRPS_IN_CASE;
					result->type = TSMRPT_RULE;
					result->rule_val = palloc0(sizeof(TSMapRule));
				}
				else if (*parse_state == TSMRPS_IN_COMMAND)
				{
					result->type = TSMRPT_COMMAND;
					result->command_val = palloc0(sizeof(TSMapCommand));
				}
				else if (*parse_state == TSMRPS_IN_CONDITION)
				{
					result->type = TSMRPT_CONDITION;
					result->condition_val = palloc0(sizeof(TSMapCondition));
				}
				else if (*parse_state == TSMRPS_IN_EXPRESSION)
				{
					result->type = TSMRPT_EXPRESSION;
					result->expression_val = palloc0(sizeof(TSMapExpression));
				}
				break;
			case WJB_END_OBJECT:
				if (*parse_state == TSMRPS_IN_CASE)
					*parse_state = TSMRPS_IN_CASES_ARRAY;
				else if (*parse_state == TSMRPS_IN_CONDITION || *parse_state == TSMRPS_IN_COMMAND)
					*parse_state = TSMRPS_IN_CASE;
				if (rule_list && result->type == TSMRPT_RULE)
				{
					rule_list->count++;
					if (rule_list->data)
						rule_list->data = repalloc(rule_list->data, sizeof(TSMapRule) * rule_list->count);
					else
						rule_list->data = palloc0(sizeof(TSMapRule) * rule_list->count);
					memcpy(rule_list->data + rule_list->count - 1, result->rule_val, sizeof(TSMapRule));
				}
				else
					return result;
			case WJB_END_ARRAY:
				break;
			default:
				nested_result = JsonbToTSMapParseObject(&val, parse_state);
				if (nested_result->type == TSMRPT_NUMERIC)
				{
					if (*parse_state == TSMRPS_IN_CASES_ARRAY)
					{
						/* Add dictionary Oid into array (comma-separated configuration) */
						rule_list->count++;
						if (rule_list->data)
							rule_list->data = repalloc(rule_list->data, sizeof(TSMapRule) * rule_list->count);
						else
							rule_list->data = palloc0(sizeof(TSMapRule) * rule_list->count);
						memset(rule_list->data + rule_list->count - 1, 0, sizeof(TSMapRule));
						rule_list->data[rule_list->count - 1].dictionary = nested_result->num_val;
					}
					else if (result->type == TSMRPT_UNKNOWN && *parse_state == TSMRPS_IN_EXPRESSION)
					{
						result->type = TSMRPT_EXPRESSION;
						result->expression_val = palloc0(sizeof(TSMapExpression));
					}
					if (result->type == TSMRPT_EXPRESSION)
						result->expression_val->dictionary = nested_result->num_val;
				}
				else if (nested_result->type == TSMRPT_RULE && rule_list)
				{
					rule_list->count++;
					if (rule_list->data)
						rule_list->data = repalloc(rule_list->data, sizeof(TSMapRule) * rule_list->count);
					else
						rule_list->data = palloc0(sizeof(TSMapRule) * rule_list->count);
					memcpy(rule_list->data + rule_list->count - 1, nested_result->rule_val, sizeof(TSMapRule));
				}
				break;
		}
	}
	result->type = TSMRPT_RULE_LIST;
	result->rule_list_val = rule_list;
	return result;
}

TSMapRuleList *
JsonbToTSMap(Jsonb *json)
{
	JsonbContainer *root = &json->root;
	TSMapRuleList  *result = palloc0(sizeof(TSMapRuleList));
	TSMapRuleParseState parse_state = TSMRPS_BEGINING;
	TSMapParseNode *parsing_result;

	parsing_result = JsonbToTSMapParse(root, &parse_state);

	Assert(parsing_result->type == TSMRPT_RULE_LIST);
	result = parsing_result->rule_list_val;
	pfree(parsing_result);

	return result;
}

/*
 * Since field order in bit fields is not guaranteed, make a manual
 * serialization/deserialization in order to keep data in common format
 * regardless bitfield structure after compilation
 */
int32
serialize_ts_configuration_operator_descriptor(TSConfigurationOperatorDescriptor operator)
{
	int32 result = 0;

	result |= operator.presented << 31;
	result |= operator.l_is_operator << 30;
	result |= operator.l_pos << 18;
	result |= operator.r_is_operator << 17;
	result |= operator.r_pos << 5;
	result |= operator.oper << 3;
	result |= operator._notused << 1;
	result |= operator.is_legacy << 0;

	return result;
}

TSConfigurationOperatorDescriptor
deserialize_ts_configuration_operator_descriptor(int32 operator)
{
	TSConfigurationOperatorDescriptor result;

	result.presented = operator >> 31;
	result.l_is_operator = operator >> 30;
	result.l_pos = operator >> 18;
	result.r_is_operator = operator >> 17;
	result.r_pos = operator >> 5;
	result.oper = operator >> 3;
	result._notused = operator >> 1;
	result.is_legacy = operator >> 0;

	return result;
}


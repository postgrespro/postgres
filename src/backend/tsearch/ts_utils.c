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

static char *
dictionary_pipe_to_text_print_options(int32 *options, int curDict)
{
	int len = 0;
	int pos = 0;
	char *result;

	if (options[curDict] == 0)
		return NULL;

	if (options[curDict] & DICTPIPE_ELEM_OPT_ACCEPT)
		len += strlen(DICTPIPE_ELEM_OPT_ACCEPT_LITERAL);

	result = palloc0(sizeof(char) * (len + 1));

	if (options[curDict] & DICTPIPE_ELEM_OPT_ACCEPT)
	{
		memcpy(result + pos, DICTPIPE_ELEM_OPT_ACCEPT_LITERAL, sizeof(char) * strlen(DICTPIPE_ELEM_OPT_ACCEPT_LITERAL));
		pos += strlen(DICTPIPE_ELEM_OPT_ACCEPT_LITERAL);
	}

	return result;
}

static char *
dictionary_pipe_to_text_print_dict(Oid *dictIds, int32 *options, int curDict)
{
	Relation							maprel;
	Relation							mapidx;
	ScanKeyData							mapskey;
	SysScanDesc							mapscan;
	HeapTuple							maptup;
	Form_pg_ts_dict						dict;
	char							   *result;

	maprel = heap_open(TSDictionaryRelationId, AccessShareLock);
	mapidx = index_open(TSDictionaryOidIndexId, AccessShareLock);

	ScanKeyInit(&mapskey, ObjectIdAttributeNumber,
			BTEqualStrategyNumber, F_OIDEQ,
			ObjectIdGetDatum(dictIds[curDict]));
	mapscan = systable_beginscan_ordered(maprel, mapidx,
									 NULL, 1, &mapskey);

	maptup = systable_getnext_ordered(mapscan, ForwardScanDirection);
	dict = (Form_pg_ts_dict) GETSTRUCT(maptup);
	result = palloc0(sizeof(char) * (strlen(dict->dictname.data) + 1));
	memcpy(result, dict->dictname.data, sizeof(char) * strlen(dict->dictname.data));

	systable_endscan_ordered(mapscan);
	index_close(mapidx, AccessShareLock);
	heap_close(maprel, AccessShareLock);

	if (options[curDict])
	{
		char *tmp = result;
		char *options_str = dictionary_pipe_to_text_print_options(options, curDict);
		result = palloc0(sizeof(char) * (strlen(tmp) + strlen(options_str) + 3));
		memcpy(result, tmp, sizeof(char) * strlen(tmp));
		result[strlen(tmp)] = '(';
		memcpy(result + strlen(tmp) + 1, options_str, sizeof(char) * strlen(options_str));
		result[strlen(tmp) + strlen(options_str) + 1] = ')';
	}

	return result;
}

static char *
dictionary_pipe_to_text_recurse(Oid *dictIds, int32 *options,
		TSConfigurationOperatorDescriptor *operators, int curOperator)
{
	char							   *l_name;
	char							   *operator_name;
	char							   *r_name;
	char							   *result;
	TSConfigurationOperatorDescriptor	operator = operators[curOperator];

	if (operator.l_is_operator)
	{
		l_name = dictionary_pipe_to_text_recurse(dictIds, options, operators, operator.l_pos);
		if (operators[operator.l_pos].oper < operator.oper)
		{
			char *tmp = l_name;
			l_name = palloc0(sizeof(char) * (strlen(tmp) + 3));
			l_name[0] = '(';
			memcpy(l_name + 1, tmp, sizeof(char) * strlen(tmp));
			l_name[strlen(tmp) + 1] = ')';
			pfree(tmp);
		}
	}
	else
	{
		l_name = dictionary_pipe_to_text_print_dict(dictIds, options, operator.l_pos);
	}

	switch (operator.oper)
	{
		case DICTPIPE_OP_AND:
			operator_name = " AND ";
			break;
		case DICTPIPE_OP_OR:
			if (operator.is_legacy)
				operator_name = ", ";
			else
				operator_name = " OR ";
			break;
		case DICTPIPE_OP_THEN:
			operator_name = " THEN ";
			break;
	}

	if (operator.r_is_operator)
	{
		r_name = dictionary_pipe_to_text_recurse(dictIds, options, operators, operator.r_pos);
		if (operators[operator.r_pos].oper < operator.oper)
		{
			char *tmp = r_name;
			r_name = palloc0(sizeof(char) * (strlen(tmp) + 3));
			r_name[0] = '(';
			memcpy(r_name + 1, tmp, sizeof(char) * strlen(tmp));
			r_name[strlen(tmp) + 1] = ')';
			pfree(tmp);
		}
	}
	else
	{
		r_name = dictionary_pipe_to_text_print_dict(dictIds, options, operator.r_pos);
	}

	result = palloc0(sizeof(char) * (strlen(l_name) + strlen(operator_name) + strlen(r_name) + 1));
	memcpy(result, l_name, sizeof(char) * strlen(l_name));
	memcpy(result + strlen(l_name), operator_name, sizeof(char) * strlen(operator_name));
	memcpy(result + strlen(l_name) + strlen(operator_name), r_name, sizeof(char) * strlen(r_name));

	pfree(l_name);
	pfree(r_name);

	return result;
}

Datum
dictionary_pipe_to_text(PG_FUNCTION_ARGS)
{
	Oid									cfgOid = PG_GETARG_OID(0);
	int32								tokentype = PG_GETARG_INT32(1);
	char							   *rawResult;
	text							   *result;
	TSConfigCacheEntry				   *cacheEntry;

	cacheEntry = lookup_ts_config_cache(cfgOid);

	if (cacheEntry->map[tokentype].len > 1)
		rawResult = dictionary_pipe_to_text_recurse(cacheEntry->map[tokentype].dictIds,
													cacheEntry->map[tokentype].dictOptions,
													cacheEntry->operators[tokentype].operators,
													0);
	else
		rawResult = dictionary_pipe_to_text_print_dict(	cacheEntry->map[tokentype].dictIds,
														cacheEntry->map[tokentype].dictOptions,
														0);
	result = cstring_to_text(rawResult);
	pfree(rawResult);

	PG_RETURN_TEXT_P(result);
}


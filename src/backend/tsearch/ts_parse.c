/*-------------------------------------------------------------------------
 *
 * ts_parse.c
 *		main parse functions for tsearch
 *
 * Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/tsearch/ts_parse.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "tsearch/ts_cache.h"
#include "tsearch/ts_utils.h"
#include "catalog/pg_ts_config_map.h"

#define IGNORE_LONGLEXEME	1

/*
 * Lexize subsystem
 */

typedef struct ParsedLex
{
	int			type;
	char	   *lemm;
	int			lenlemm;
	bool	   *accepted;
	bool	   *rejected;
	bool	   *notFinished;
	bool	   *holdAccepted;
	struct ParsedLex *next;
} ParsedLex;

typedef struct ListParsedLex
{
	ParsedLex  *head;
	ParsedLex  *tail;
} ListParsedLex;

typedef struct
{
	TSConfigCacheEntry *cfg;
	Oid			curDictId;
	int			posDict;
	DictSubState dictState;
	ParsedLex  *curSub;
	ListParsedLex towork;		/* current list to work */
	ListParsedLex waste;		/* list of lexemes that already lexized */

	/*
	 * field to store last variant to lexize (basically, thesaurus or similar
	 * to, which wants	several lexemes
	 */
	TSLexeme   *tmpRes;
} LexizeData;

static bool IsOperatorRejected(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator);
static TSLexeme *LexizeExec(LexizeData *ld, ParsedLex **correspondLexem);
static TSLexeme *LexizeExecOperator(TSConfigCacheEntry *cfg, ParsedLex *curVal, 
		TSConfigurationOperatorDescriptor operator, LexizeData *ld, ParsedLex **correspondLexem);
static TSLexeme *LexizeExecDictionary(LexizeData *ld, ParsedLex **correspondLexem, int dictPos);

static void
LexizeInit(LexizeData *ld, TSConfigCacheEntry *cfg)
{
	ld->cfg = cfg;
	ld->curDictId = InvalidOid;
	ld->posDict = 0;
	ld->towork.head = ld->towork.tail = ld->curSub = NULL;
	ld->waste.head = ld->waste.tail = NULL;
	ld->tmpRes = NULL;
}

static void
LPLAddTail(ListParsedLex *list, ParsedLex *newpl)
{
	if (list->tail)
	{
		list->tail->next = newpl;
		list->tail = newpl;
	}
	else
		list->head = list->tail = newpl;
	newpl->next = NULL;
}

static ParsedLex *
LPLRemoveHead(ListParsedLex *list)
{
	ParsedLex  *res = list->head;

	if (list->head)
		list->head = list->head->next;

	if (list->head == NULL)
		list->tail = NULL;

	return res;
}

static void
LexizeAddLemm(LexizeData *ld, int type, char *lemm, int lenlemm)
{
	ParsedLex  *newpl = (ParsedLex *) palloc(sizeof(ParsedLex));
	int len;

	if (type != 0 && (type >= ld->cfg->lenmap))
	{
		len = 1;
	}
	else
	{
		ListDictionary	   *map = ld->cfg->map + type;
		len = map->len;
	}

	newpl->type = type;
	newpl->lemm = lemm;
	newpl->lenlemm = lenlemm;
	newpl->accepted = palloc0(sizeof(bool) * len);
	newpl->rejected = palloc0(sizeof(bool) * len);
	newpl->notFinished = palloc0(sizeof(bool) * len);
	newpl->holdAccepted = palloc0(sizeof(bool) * len);
	LPLAddTail(&ld->towork, newpl);
	ld->curSub = ld->towork.tail;
}

static void
RemoveHead(LexizeData *ld)
{
	LPLAddTail(&ld->waste, LPLRemoveHead(&ld->towork));

	ld->posDict = 0;
}

static void
setCorrLex(LexizeData *ld, ParsedLex **correspondLexem)
{
	if (correspondLexem)
	{
		*correspondLexem = ld->waste.head;
	}
	else
	{
		ParsedLex  *tmp,
				   *ptr = ld->waste.head;

		while (ptr)
		{
			tmp = ptr->next;
			pfree(ptr);
			ptr = tmp;
		}
	}
	ld->waste.head = ld->waste.tail = NULL;
}

static int
TSLexemeGetSize(TSLexeme *lexeme)
{
	int res = 0;
	while (lexeme != NULL && lexeme->lexeme)
	{
		res++;
		lexeme++;
	}
	return res;
}

static void
setNewTmpRes(LexizeData *ld, ParsedLex *lex, TSLexeme *res)
{
	int i;
	if (ld->tmpRes)
	{
		TSLexeme   *ptr;

		for (ptr = ld->tmpRes; ptr->lexeme; ptr++)
			pfree(ptr->lexeme);
		pfree(ld->tmpRes);
	}
	ld->tmpRes = palloc0(sizeof(TSLexeme) * (TSLexemeGetSize(res) + 1));
	for (i = 0; i < TSLexemeGetSize(res); i++)
	{
		ld->tmpRes[i].flags = res[i].flags;
		ld->tmpRes[i].nvariant = res[i].nvariant;
		ld->tmpRes[i].lexeme = palloc0(sizeof(char) * (strlen(res[i].lexeme) + 1));
		memcpy(ld->tmpRes[i].lexeme, res[i].lexeme, sizeof(char) * strlen(res[i].lexeme));
	}
}

static TSLexeme *
TSLexemeCombine(TSLexeme *left, TSLexeme *right)
{
	int leftSize;
	int rightSize;
	int nvariant;
	TSLexeme *res;
	TSLexeme *ptr;

	if (left == NULL && right == NULL)
		return NULL;

	leftSize = TSLexemeGetSize(left);
	rightSize = TSLexemeGetSize(right);
	res = palloc0(sizeof(TSLexeme) * (leftSize + rightSize + 1));

	nvariant = 0;
	if (leftSize > 0)
		for (ptr = left; ptr->lexeme; ptr++)
			if (ptr->nvariant > nvariant)
				nvariant = ptr->nvariant + 1;

	if (leftSize > 0)
		memcpy(res, left, sizeof(TSLexeme) * leftSize);
	if (rightSize > 0)
		memcpy(res + leftSize, right, sizeof(TSLexeme) * (rightSize + 1));

	/*
	 * Increase nvariant of right-side by the maxixmum nvariant of the
	 * left-side to avoid collisions
	 */
	if (leftSize > 0)
		for (ptr = res + leftSize; ptr->lexeme; ptr++)
			ptr->nvariant += nvariant + 1;

	return res;
}

static bool
IsOperatorAccepted(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	bool						l_accepted = false;
	bool						r_accepted = false;
	bool						l_rejected = false;
	bool						r_rejected = false;

	l_accepted = operator.l_is_operator ? IsOperatorAccepted(cfg, curVal, operators->operators[operator.l_pos])
		: curVal->accepted[operator.l_pos];
	r_accepted = operator.r_is_operator ? IsOperatorAccepted(cfg, curVal, operators->operators[operator.r_pos])
		: curVal->accepted[operator.r_pos];

	l_rejected = operator.l_is_operator ? IsOperatorRejected(cfg, curVal, operators->operators[operator.l_pos])
		: curVal->rejected[operator.l_pos];
	r_rejected = operator.r_is_operator ? IsOperatorRejected(cfg, curVal, operators->operators[operator.r_pos])
		: curVal->rejected[operator.r_pos];

	switch (operator.oper)
	{
		case DICTPIPE_OP_OR:
			return l_accepted || r_accepted;
		case DICTPIPE_OP_AND:
			return (l_accepted && r_accepted) || (l_rejected && r_accepted) || (l_accepted && r_rejected);
		case DICTPIPE_OP_THEN:
			return !l_accepted || r_accepted;
		default:
			return false;
	}
}

static bool
IsOperatorRejected(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	bool						l_rejected = false;
	bool						r_rejected = false;

	l_rejected = operator.l_is_operator ? IsOperatorRejected(cfg, curVal, operators->operators[operator.l_pos])
		: curVal->rejected[operator.l_pos];
	r_rejected = operator.r_is_operator ? IsOperatorRejected(cfg, curVal, operators->operators[operator.r_pos])
		: curVal->rejected[operator.r_pos];

	return l_rejected && r_rejected;
}

static bool
IsNotFinished(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	bool						l_not_fully_finished = false;
	bool						r_not_fully_finished = false;

	if (operator.l_is_operator)
		l_not_fully_finished = IsNotFinished(cfg, curVal, operators->operators[operator.l_pos]);
	else
		l_not_fully_finished = curVal->notFinished[operator.l_pos];

	if (operator.r_is_operator)
		r_not_fully_finished = IsNotFinished(cfg, curVal, operators->operators[operator.r_pos]);
	else
		r_not_fully_finished = curVal->notFinished[operator.r_pos];

	return l_not_fully_finished || r_not_fully_finished;
}

static bool
IsProcessingComplete(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	ListDictionary			   *map = cfg->map + curVal->type;
	bool						l_accepted = false;
	bool						r_accepted = false;
	bool						l_rejected = false;
	bool						r_rejected = false;
	bool						l_not_finished = false;
	bool						r_not_finished = false;

	if (operator.l_is_operator)
	{
		l_accepted = IsOperatorAccepted(cfg, curVal, operators->operators[operator.l_pos]);
		l_rejected = IsOperatorRejected(cfg, curVal, operators->operators[operator.l_pos]);
		l_not_finished = IsNotFinished(cfg, curVal, operators->operators[operator.l_pos]);
	}
	else
	{
		l_accepted = curVal->accepted[operator.l_pos];
		l_rejected = curVal->rejected[operator.l_pos];
		l_not_finished = curVal->notFinished[operator.l_pos];
	}
	if (operator.r_is_operator)
	{
		r_accepted = IsOperatorAccepted(cfg, curVal, operators->operators[operator.r_pos]);
		r_rejected = IsOperatorRejected(cfg, curVal, operators->operators[operator.r_pos]);
		r_not_finished = IsNotFinished(cfg, curVal, operators->operators[operator.r_pos]);
	}
	else
	{
		r_accepted = curVal->accepted[operator.r_pos];
		r_rejected = curVal->rejected[operator.r_pos];
		r_not_finished = curVal->notFinished[operator.r_pos];
	}

	switch (operator.oper)
	{
		case DICTPIPE_OP_OR:
			return (l_accepted && !l_not_finished) || (l_rejected && r_accepted && !r_not_finished) || (l_rejected && r_rejected);
		case DICTPIPE_OP_AND:
			return ((l_accepted && !l_not_finished) || l_rejected) && ((r_accepted && !r_not_finished) || r_rejected);
		case DICTPIPE_OP_THEN:
			return (l_accepted && !l_not_finished && r_accepted && !r_not_finished) || (l_rejected && r_accepted && !r_not_finished) ||
				(l_rejected && (operator.l_is_operator == 0) && ((map->dictOptions[operator.l_pos] & DICTPIPE_ELEM_OPT_ACCEPT) == 0));
		default:
			return false;
	}
}

static bool
IsLeftSideProcessingComplete(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	bool						l_accepted = false;
	bool						l_rejected = false;
	bool						l_not_finished = false;

	if (curVal->type == 0)
		return true;

	if (operator.l_is_operator)
	{
		return IsProcessingComplete(cfg, curVal, operators->operators[operator.l_pos]);
	}
	else
	{
		l_accepted = curVal->accepted[operator.l_pos];
		l_rejected = curVal->rejected[operator.l_pos];
		l_not_finished = curVal->notFinished[operator.l_pos];
		return (l_accepted && !l_not_finished) || l_rejected;
	}
}

static bool
IsLeftSideRejected(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	bool						l_rejected = false;

	if (operator.l_is_operator)
		l_rejected = IsOperatorRejected(cfg, curVal, operators->operators[operator.l_pos]);
	else
		l_rejected = curVal->rejected[operator.l_pos];

	return l_rejected;
}


static bool
IsRightSideProcessingComplete(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	bool						r_accepted = false;
	bool						r_rejected = false;
	bool						r_not_finished = false;

	if (curVal->type == 0)
		return true;

	if (operator.r_is_operator)
	{
		return IsProcessingComplete(cfg, curVal, operators->operators[operator.r_pos]);
	}
	else
	{
		r_accepted = curVal->accepted[operator.r_pos];
		r_rejected = curVal->rejected[operator.r_pos];
		r_not_finished = curVal->notFinished[operator.r_pos];
		return (r_accepted && !r_not_finished) || r_rejected;
	}
}

static void
MarkAsRejected(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;

	if (operator.l_is_operator)
		MarkAsRejected(cfg, curVal, operators->operators[operator.l_pos]);
	else
		curVal->rejected[operator.l_pos] = true;

	if (operator.r_is_operator)
		MarkAsRejected(cfg, curVal, operators->operators[operator.r_pos]);
	else
		curVal->rejected[operator.r_pos] = true;
}

static void
UnmarkBranchAsAccepted(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;

	if (operator.l_is_operator)
		UnmarkBranchAsAccepted(cfg, curVal, operators->operators[operator.l_pos]);
	else
		curVal->accepted[operator.l_pos] = false;

	if (operator.r_is_operator)
		UnmarkBranchAsAccepted(cfg, curVal, operators->operators[operator.r_pos]);
	else
		curVal->accepted[operator.r_pos] = false;
}

static void
CopyCompletionMarks(TSConfigCacheEntry *cfg, ParsedLex *from, ParsedLex *to,
		TSConfigurationOperatorDescriptor operator)
{
	ListDictionaryOperators	   *operators = cfg->operators + to->type;

	if (operator.l_is_operator)
		CopyCompletionMarks(cfg, from, to, operators->operators[operator.l_pos]);
	else
	{
		to->accepted[operator.l_pos] = from->accepted[operator.l_pos];
		to->rejected[operator.l_pos] = from->rejected[operator.l_pos];
		to->notFinished[operator.l_pos] = from->notFinished[operator.l_pos];
	}

	if (operator.r_is_operator)
		CopyCompletionMarks(cfg, from, to, operators->operators[operator.r_pos]);
	else
	{
		to->accepted[operator.r_pos] = from->accepted[operator.r_pos];
		to->rejected[operator.r_pos] = from->rejected[operator.r_pos];
		to->notFinished[operator.r_pos] = from->notFinished[operator.r_pos];
	}
}

static ParsedLex *
CopyParsedLex(ParsedLex *pl, int mapLen)
{
	ParsedLex  *res = palloc0(sizeof(ParsedLex));

	memcpy(res, pl, sizeof(ParsedLex));

	res->accepted = palloc0(sizeof(bool) * mapLen);
	res->rejected = palloc0(sizeof(bool) * mapLen);
	res->notFinished = palloc0(sizeof(bool) * mapLen);
	res->holdAccepted = palloc0(sizeof(bool) * mapLen);

	memcpy(res->accepted, pl->accepted, sizeof(bool) * mapLen);
	memcpy(res->rejected, pl->rejected, sizeof(bool) * mapLen);
	memcpy(res->notFinished, pl->notFinished, sizeof(bool) * mapLen);
	memcpy(res->holdAccepted, pl->holdAccepted, sizeof(bool) * mapLen);

	return res;
}

static void
MergeParsedLexFlags(ParsedLex *to, ParsedLex *from, int mapLen)
{
	int i;
	for (i = 0; i < mapLen; i++)
	{
		to->accepted[i] = to->accepted[i] || from->accepted[i];
		to->rejected[i] = to->rejected[i] || from->rejected[i];
		to->notFinished[i] = to->notFinished[i] || from->notFinished[i];
		to->holdAccepted[i] = to->holdAccepted[i] || from->holdAccepted[i];
	}
}

static TSLexeme *
LexizeExecOperatorThen(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator, LexizeData *ld, ParsedLex **correspondLexem)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	ListDictionary			   *map = cfg->map + curVal->type;
	TSLexeme				   *leftRes;
	TSLexeme				   *rightRes;
	TSLexeme				   *res;
	TSLexeme				  **thenRightRes;
	ParsedLex				   *nonProcessedLex;
	ParsedLex				   *resCurVal;
	int						   *thenRightSizes;
	int							nvariant;
	int							i;
	int							resSize;
	int							leftSize;
	int							rightSize;
	bool						noResults = true;

	if (IsLeftSideProcessingComplete(cfg, curVal, operator) && IsRightSideProcessingComplete(cfg, curVal, operator))
		return NULL;

	leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], ld, correspondLexem)
		: LexizeExecDictionary(ld, correspondLexem, operator.l_pos);
	
	// Wait until next execution for more lexemes
	if (!IsLeftSideProcessingComplete(cfg, curVal, operator))
		return NULL;

	/*
	 * If there is no output, transfer control to the next dictionary or
	 * return NULL based on configuration
	 */
	if (IsLeftSideRejected(cfg, curVal, operator))
	{
		if (operator.l_is_operator == 0 && map->dictOptions[operator.l_pos] & DICTPIPE_ELEM_OPT_ACCEPT)
		{
			return operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], ld, correspondLexem)
				: LexizeExecDictionary(ld, correspondLexem, operator.r_pos);
		}
		else
		{
			// Mark right-side as rejected in order to skip possible processing in future
			if (operator.r_is_operator)
				MarkAsRejected(cfg, curVal, operators->operators[operator.r_pos]);
			else
				curVal->rejected[operator.r_pos] = true;
			return NULL;
		}
	}

	resSize = 0;
	res = palloc0(sizeof(TSLexeme));
	leftSize = TSLexemeGetSize(leftRes);
	thenRightRes = palloc0(sizeof(TSLexeme*) * leftSize);
	thenRightSizes = palloc0(sizeof(int) * leftSize);

	// Find first lexem that is not processed by left-side subexpression
	nonProcessedLex = curVal->next;
	while (nonProcessedLex && nonProcessedLex->type != 0 && IsLeftSideProcessingComplete(cfg, nonProcessedLex, operator))
		nonProcessedLex = nonProcessedLex->next;
	resCurVal = CopyParsedLex(curVal, map->len);

	/*
	 * Store right-side results in array of pointers, in order to
	 * allocate result TSLexeme array in one call without reallocations
	 * for each right-side result
	 */
	for (i = 0; i < leftSize; i++)
	{
		TSLexeme   *ptr;
		ParsedLex  *processedLex = curVal->next;
		ParsedLex  *curValSub = NULL;
		ParsedLex  *curValSubLast = NULL;
		int			j = i + 1;

		curValSub = CopyParsedLex(curVal, map->len);
		curValSub->next = nonProcessedLex;

		curValSub->lemm = leftRes[i].lexeme;
		curValSub->lenlemm = strlen(leftRes[i].lexeme);

		ld->towork.head = curValSub;
		curValSubLast = curValSub;

		// Add all lexemes with same nvariant in order to process it as a phrase
		while (j < leftSize && leftRes[i].nvariant == leftRes[j].nvariant)
		{
			ParsedLex *curValSubNext = CopyParsedLex(curVal, map->len);

			curValSubNext->lemm = leftRes[j].lexeme;
			curValSubNext->lenlemm = strlen(leftRes[j].lexeme);
			curValSubLast->next = curValSubNext;
			curValSubNext->next = nonProcessedLex;
			curValSubLast = curValSubNext ;
			j++;
		}

		while (curValSub != nonProcessedLex)
		{
			TSLexeme *curRes;
			TSLexeme *prevRes = thenRightRes[i];
			curRes = operator.r_is_operator ? LexizeExecOperator(cfg, curValSub, operators->operators[operator.r_pos], ld, correspondLexem)
				: LexizeExecDictionary(ld, correspondLexem, operator.r_pos);
			if (prevRes && curRes)
				curRes->flags |= TSL_ADDPOS;
			thenRightRes[i] = TSLexemeCombine(prevRes, curRes);
			MergeParsedLexFlags(resCurVal, curValSub, map->len);
			if (prevRes)
				pfree(prevRes);
			if (curRes)
				pfree(curRes);
			if (IsRightSideProcessingComplete(cfg, curValSub, operator))
			{
				ld->towork.head = curValSub->next;
				pfree(curValSub);
				curValSub = ld->towork.head;
			}
			else
			{
				/*
				 * The dictionary didn't complete the processing of current 
				 * lexeme, stop processing and revert flags in order to
				 * process it during next iteration with more lexemes in
				 * the queue
				 */
				memcpy(resCurVal->accepted, curVal->accepted, sizeof(bool) * map->len);
				memcpy(resCurVal->rejected, curVal->rejected, sizeof(bool) * map->len);
				memcpy(resCurVal->notFinished, curVal->notFinished, sizeof(bool) * map->len);
				memcpy(resCurVal->holdAccepted, curVal->holdAccepted, sizeof(bool) * map->len);
				j = leftSize;
				thenRightRes[i] = NULL;
				break;
			}
		}

		/*
		 * Copy flags of lexemes processed by right subexpression
		 * to all lexemes processed by left subexpression, since all of then
		 * are processed the same way (in terms of completeness)
		 */
		while (processedLex && processedLex != nonProcessedLex)
		{
			if (operator.r_is_operator)
				CopyCompletionMarks(cfg, resCurVal, processedLex, operators->operators[operator.r_pos]);
			else
			{
				ListDictionary *ptr_map = cfg->map + processedLex->type;
				if (map->len == ptr_map->len && map->dictIds[operator.r_pos] == ptr_map->dictIds[operator.r_pos])
				{
					processedLex->accepted[operator.r_pos] = resCurVal->accepted[operator.r_pos];
					processedLex->rejected[operator.r_pos] = resCurVal->rejected[operator.r_pos];
					processedLex->notFinished[operator.r_pos] = resCurVal->notFinished[operator.r_pos];
					processedLex->holdAccepted[operator.r_pos] = resCurVal->holdAccepted[operator.r_pos];
				}
			}
			processedLex = processedLex->next;
		}

		if (thenRightRes[i] != NULL)
			noResults = false;

		ptr = thenRightRes[i];
		while (ptr && ptr->lexeme)
		{
			ptr->flags |= leftRes[i].flags;
			ptr++;
		}

		thenRightSizes[i] = TSLexemeGetSize(thenRightRes[i]);
		resSize += thenRightSizes[i];
		i = j - 1;
	}

	MergeParsedLexFlags(curVal, resCurVal, map->len);

	if (noResults)
	{
		res = NULL;
		if (!IsRightSideProcessingComplete(cfg, curVal, operator))
		{
			if (operator.l_is_operator)
				UnmarkBranchAsAccepted(cfg, curVal, operators->operators[operator.l_pos]);
			else
				curVal->accepted[operator.l_pos] = false;
		}
	}
	else
	{
		/*
		 * Combine all output into one lexemes list
		 */

		res = palloc0(sizeof(TSLexeme) * (resSize + 1));
		rightSize = 0;
		nvariant = 0;
		for (i = 0; i < leftSize; i++)
		{
			if (thenRightRes[i] != NULL)
			{
				/*
				 * Increase nvariant of the results to avoid nvariant collisions
				 */
				rightRes = thenRightRes[i];
				while (rightRes->lexeme != NULL)
				{
					rightRes->nvariant += nvariant + 1;
					rightRes++;
				}

				memcpy(res + rightSize, thenRightRes[i], sizeof(TSLexeme) * thenRightSizes[i]);
				rightSize += thenRightSizes[i];

				/*
				 * Update maximum nvariant already used
				 */
				rightRes = thenRightRes[i];
				while (rightRes->lexeme != NULL)
				{
					if (nvariant < rightRes->nvariant)
						nvariant = rightRes->nvariant;
					rightRes++;
				}

				pfree(thenRightRes[i]);
			}
		}
	}

	pfree(thenRightSizes);
	pfree(thenRightRes);
	ld->towork.head = curVal;

	return res;
}

static TSLexeme *
LexizeExecOperatorOr(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator, LexizeData *ld, ParsedLex **correspondLexem)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	TSLexeme				   *leftRes;

	leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], ld, correspondLexem)
		: LexizeExecDictionary(ld, correspondLexem, operator.l_pos);

	if (IsLeftSideRejected(cfg, curVal, operator))
	{
		return operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], ld, correspondLexem)
				: LexizeExecDictionary(ld, correspondLexem, operator.r_pos);
	}
	else
	{
		/*
		 * Check for flags to simulate TSL_FILTER behavior in 
		 * backward compatible mode
		 */
		if (leftRes && operator.is_legacy && leftRes->flags & TSL_FILTER)
		{
			TSLexeme	   *res;
			ParsedLex	   *newCurVal = palloc(sizeof(ParsedLex));

			memcpy(newCurVal, curVal, sizeof(ParsedLex));
			newCurVal->lemm = leftRes->lexeme;
			newCurVal->lenlemm = strlen(leftRes->lexeme);
			ld->towork.head = newCurVal;
			res = operator.r_is_operator ? LexizeExecOperator(cfg, newCurVal, operators->operators[operator.r_pos], ld, correspondLexem)
					: LexizeExecDictionary(ld, correspondLexem, operator.r_pos);
			if (operator.r_is_operator)
				CopyCompletionMarks(cfg, newCurVal, curVal, operators->operators[operator.r_pos]);
			else
			{
				ListDictionary	   *map = cfg->map + curVal->type;
				ListDictionary	   *ptr_map = cfg->map + curVal->type;

				if (map->len == ptr_map->len && map->dictIds[operator.r_pos] == ptr_map->dictIds[operator.r_pos])
				{
					curVal->accepted[operator.r_pos] = newCurVal->accepted[operator.r_pos];
					curVal->rejected[operator.r_pos] = newCurVal->rejected[operator.r_pos];
					curVal->notFinished[operator.r_pos] = newCurVal->notFinished[operator.r_pos];
				}
			}
			ld->towork.head = curVal;
			pfree(newCurVal);
			pfree(leftRes);
			return res;
		}
		return leftRes;
	}
}

static TSLexeme *
LexizeExecOperatorAnd(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator, LexizeData *ld, ParsedLex **correspondLexem)
{
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	TSLexeme				   *leftRes;
	TSLexeme				   *rightRes;
	TSLexeme				   *res;

	leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], ld, correspondLexem)
		: LexizeExecDictionary(ld, correspondLexem, operator.l_pos);

	rightRes = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], ld, correspondLexem)
		: LexizeExecDictionary(ld, correspondLexem, operator.r_pos);

	res = TSLexemeCombine(leftRes, rightRes);
	return res;
}

static TSLexeme *
LexizeExecOperator(TSConfigCacheEntry *cfg, ParsedLex *curVal, 
		TSConfigurationOperatorDescriptor operator, LexizeData *ld, ParsedLex **correspondLexem)
{
	Assert(operator.presented == 1);

	if (IsProcessingComplete(cfg, curVal, operator))
		return NULL;

	switch (operator.oper)
	{
		case DICTPIPE_OP_THEN:
			return LexizeExecOperatorThen(cfg, curVal, operator, ld, correspondLexem);
		case DICTPIPE_OP_OR:
			return LexizeExecOperatorOr(cfg, curVal, operator, ld, correspondLexem);
		case DICTPIPE_OP_AND:
			return LexizeExecOperatorAnd(cfg, curVal, operator, ld, correspondLexem);
		default:
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("Operator entry in text search configuration is corrupted"),
					 errdetail("Operator id %d is invalid.",
							   operator.oper)));
			return NULL;
	}
}

static TSLexeme *
LexizeExecDictionary(LexizeData *ld, ParsedLex **correspondLexem, int dictPos)
{
	ParsedLex				   *curVal;
	TSDictionaryCacheEntry	   *dict;
	TSLexeme				   *res = NULL;
	ListDictionary			   *map;
	int							dictId;
	int							i;

	curVal = ld->towork.head;
	map = ld->cfg->map + curVal->type;
	dictId = map->dictIds[dictPos];
	dict = lookup_ts_dictionary_cache(dictId);

	if ((curVal->accepted[dictPos] && !curVal->notFinished[dictPos]) || curVal->rejected[dictPos])
		return NULL;

	if (ld->curDictId == InvalidOid) /* Standard mode */
	{
		ld->dictState.isend = ld->dictState.getnext = false;
		ld->dictState.private_state = NULL;
		res = (TSLexeme *) DatumGetPointer(FunctionCall4(
													 &(dict->lexize),
									 PointerGetDatum(dict->dictData),
									   PointerGetDatum(curVal->lemm),
									  Int32GetDatum(curVal->lenlemm),
									  PointerGetDatum(&ld->dictState)
														 ));

		if (ld->dictState.getnext)
		{
			/*
			 * Dictionary wants next word, so setup custom context for the
			 * dictionary and go to multi-input mode
			 */
			ParsedLex *ptr = curVal;
			if (res)
			{
				setNewTmpRes(ld, curVal, res);
				curVal->accepted[dictPos] = true;
			}
			curVal->notFinished[dictPos] = true;

			ld->curDictId = dict->dictId;
			ld->curSub = curVal->next;
			res = LexizeExecDictionary(ld, correspondLexem, dictPos);
			ld->curDictId = InvalidOid;

			while (ptr)
			{
				if (ptr->type == curVal->type)
				{
					if (!res)
						ptr->accepted[dictPos] = false;
					ptr->notFinished[dictPos] = false;
				}
				ptr = ptr->next;
			}

			return res;
		}
		if (res)
			curVal->accepted[dictPos] = true;
		else
			curVal->rejected[dictPos] = true;
		return res;
	}
	else /* Process multi-input dictionary with saved state */
	{
		ParsedLex *ptr;

		curVal = ld->curSub;

		while (curVal)
		{
			while (curVal)
			{
				map = ld->cfg->map + curVal->type;
				if (curVal->type != 0 && (curVal->type >= ld->cfg->lenmap || map->len == 0))
				{
					/* skip this type of lexeme */
					curVal = curVal->next;
				}
				else
				{
					break;
				}
			}

			if (!curVal)
				return NULL;

			if (curVal->type != 0)
			{
				bool		dictExists = false;

				/*
				 * We should be sure that current type of lexeme is recognized
				 * by our dictionary: we just check is it exist in list of
				 * dictionaries
				 */
				for (i = 0; i < map->len && !dictExists; i++)
					if (dictId == DatumGetObjectId(map->dictIds[i]))
						dictExists = true;

				if (!dictExists)
				{
					/*
					 * Dictionary can't work with current type of lexeme,
					 * return to basic mode.
					 * If there is a tmpRes, return it, otherwise mark lexemes
					 * as rejected
					 */
					if (ld->tmpRes)
					{
						res = ld->tmpRes;
						ld->tmpRes = NULL;
						return res;
					}
					else
					{
						ptr = ld->towork.head;
						while (ptr)
						{
							ptr->rejected[dictPos] = true;
							if (ptr == curVal)
								break;
							ptr = ptr->next;
						}
						return NULL;
					}
				}
			}

			ld->dictState.isend = (curVal->type == 0) ? true : false;
			ld->dictState.getnext = false;

			res = (TSLexeme *) DatumGetPointer(FunctionCall4(
															 &(dict->lexize),
											 PointerGetDatum(dict->dictData),
											   PointerGetDatum(curVal->lemm),
											  Int32GetDatum(curVal->lenlemm),
											  PointerGetDatum(&ld->dictState)
															 ));

			if (ld->dictState.getnext)
			{
				/* Dictionary wants one more */
				if (res)
				{
					setNewTmpRes(ld, curVal, res);

					ptr = ld->towork.head;
					while (ptr)
					{
						ptr->accepted[dictPos] = true;
						ptr->notFinished[dictPos] = true;
						if (ptr == curVal)
							break;
						ptr = ptr->next;
					}
				}
				curVal = curVal->next;
				continue;
			}

			if (res || ld->tmpRes)
			{
				/*
				 * Dictionary normalizes lexemes, so we mark all
				 * used lexemes and return to basic mode
				 */
				if (!res)
				{
					res = ld->tmpRes;
				}
				else
				{
					ptr = ld->towork.head;
					while (ptr)
					{
						ptr->accepted[dictPos] = true;
						if (ptr == curVal)
							break;
						ptr = ptr->next;
					}
				}

				ptr = ld->towork.head;
				while (ptr)
				{
					ptr->notFinished[dictPos] = false;
					ptr = ptr->next;
				}
				ld->tmpRes = NULL;
				return res;
			}

			/*
			 * Dict don't want next lexem and didn't recognize anything, mark
			 * input as rejected
			 */
			ptr = ld->towork.head;
			while (ptr && ptr != curVal)
			{
				ptr->notFinished[dictPos] = false;
				ptr->rejected[dictPos] = true;
				ptr = ptr->next;
			}
			return NULL;
		}
	}
	return NULL;
}

static TSLexeme *
TSLexemeRemoveDuplications(TSLexeme *lexeme)
{
	TSLexeme	   *res;
	int				curLexIndex;
	int				i;
	int				lexemeSize = TSLexemeGetSize(lexeme);
	int				shouldCopyCount = lexemeSize;
	bool		   *shouldCopy;

	if (lexeme == NULL)
		return NULL;

	shouldCopy = palloc(sizeof(bool) * lexemeSize);
	memset(shouldCopy, true, sizeof(bool) * lexemeSize);

	for (curLexIndex = 0; curLexIndex < lexemeSize; curLexIndex++)
	{
		for (i = curLexIndex + 1; i < lexemeSize; i++)
		{
			if (!shouldCopy[i])
				continue;

			if (strcmp(lexeme[curLexIndex].lexeme, lexeme[i].lexeme) == 0)
			{
				if (lexeme[curLexIndex].nvariant == lexeme[i].nvariant)
				{
					shouldCopy[i] = false;
					shouldCopyCount--;
					continue;
				}
				else
				{
					/*
					 * Check for same set of lexemes in another nvariant series
					 */
					int		nvariantCountL = 0;
					int		nvariantCountR = 0;
					int		nvariantOverlap = 1;
					int		j;

					for (j = 0; j < lexemeSize; j++)
						if (lexeme[curLexIndex].nvariant == lexeme[j].nvariant)
							nvariantCountL++;
					for (j = 0; j < lexemeSize; j++)
						if (lexeme[i].nvariant == lexeme[j].nvariant)
							nvariantCountR++;

					if (nvariantCountL != nvariantCountR)
						continue;

					for (j = 1; j < nvariantCountR; j++)
					{
						if (strcmp(lexeme[curLexIndex + j].lexeme, lexeme[i + j].lexeme) == 0
								&& lexeme[curLexIndex + j].nvariant == lexeme[i + j].nvariant)
							nvariantOverlap++;
					}

					if (nvariantOverlap != nvariantCountR)
						continue;

					for (j = 0; j < nvariantCountR; j++)
					{
						shouldCopy[i + j] = false;
					}
				}
			}
		}
	}

	res = palloc0(sizeof(TSLexeme) * (shouldCopyCount + 1));

	for (i = 0, curLexIndex = 0; curLexIndex < lexemeSize; curLexIndex++)
	{
		if (shouldCopy[curLexIndex])
		{
			memcpy(res + i, lexeme + curLexIndex, sizeof(TSLexeme));
			i++;
		}
	}

	pfree(shouldCopy);
	pfree(lexeme);
	return res;
}

static bool
CleanToworkQueue(LexizeData *ld, ParsedLex **correspondLexem)
{
	ListDictionary			   *map;
	ListDictionaryOperators	   *operators;
	ParsedLex				   *curVal;
	bool						result = false;;

	while ((curVal = ld->towork.head) != NULL)
	{
		map = ld->cfg->map + curVal->type;
		operators = ld->cfg->operators + curVal->type;
		if ((map->len > 1 && IsProcessingComplete(ld->cfg, curVal, operators->operators[0]))
				|| (map->len == 1 && ((curVal->accepted[0] && !curVal->notFinished[0]) || curVal->rejected[0])))
		{
			ParsedLex *ptr = curVal->next;
			while (ptr)
			{
				int dictIndex = 0;
				ListDictionary *ptr_map = ld->cfg->map + ptr->type;
				for (dictIndex = 0; dictIndex < ptr_map->len; dictIndex++)
				{
					if (map->len == ptr_map->len && map->dictIds[dictIndex] == ptr_map->dictIds[dictIndex]
							&& curVal->accepted[dictIndex] && ptr->accepted[dictIndex])
						ptr->holdAccepted[dictIndex] = true;
				}
				ptr = ptr->next;
			}
			RemoveHead(ld);
			result = true;
		}
		else
		{
			break;
		}
	}
	return result;
}

static TSLexeme *
LexizeExec(LexizeData *ld, ParsedLex **correspondLexem)
{
	ListDictionary			   *map;
	ListDictionaryOperators	   *operators;
	TSLexeme				   *res = NULL;
	ParsedLex				   *curVal;

	if (ld->towork.head == NULL)
	{
		setCorrLex(ld, correspondLexem);
		return NULL;
	}

	curVal = ld->towork.head;
	map = ld->cfg->map + curVal->type;
	operators = ld->cfg->operators + curVal->type;

	if (curVal->type != 0 && (curVal->type >= ld->cfg->lenmap || map->len == 0 || operators->len == 0))
	{
		/* skip this type of lexeme */
		RemoveHead(ld);
		setCorrLex(ld, correspondLexem);
		return NULL;
	}

	if (CleanToworkQueue(ld, correspondLexem))
		return NULL;

	if (curVal->type == 0) // End of the input, finish processing of multi-input dictionaries
	{
		res = TSLexemeRemoveDuplications(res);
		RemoveHead(ld);
		setCorrLex(ld, correspondLexem);
		return res;
	}

	ld->curDictId = InvalidOid;
	if (map->len == 1) // There are no operators, just single dictionary
	{
		res = LexizeExecDictionary(ld, correspondLexem, 0);
	}
	else // There is a dictionary pipe expression tree, start from top operator
	{
		Assert(operators->len != 0);
		res = LexizeExecOperator(ld->cfg, curVal, operators->operators[0], ld, correspondLexem);
	}
	if (!((map->len > 1 && IsProcessingComplete(ld->cfg, curVal, operators->operators[0]))
			|| (map->len == 1 && ((curVal->accepted[0] && !curVal->notFinished[0]) || curVal->rejected[0]))))
	{
		// Reset accept and notFinished flags
		ParsedLex *ptr = curVal;
		while (ptr)
		{
			int dictIndex = 0;
			ListDictionary *ptr_map = ld->cfg->map + ptr->type;
			for (dictIndex = 0; dictIndex < ptr_map->len; dictIndex++)
			{
				if (!ptr->holdAccepted[dictIndex])
					ptr->accepted[dictIndex] = false;
				ptr->notFinished[dictIndex] = false;
			}
			ptr = ptr->next;
		}
		return NULL;
	}

	CleanToworkQueue(ld, correspondLexem);
	setCorrLex(ld, correspondLexem);
	return res;
}

/*
 * Parse string and lexize words.
 *
 * prs will be filled in.
 */
void
parsetext(Oid cfgId, ParsedText *prs, char *buf, int buflen)
{
	int			type = -1,
				lenlemm;
	char	   *lemm = NULL;
	LexizeData	ldata;
	TSLexeme   *norms;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	void	   *prsdata;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);

	prsdata = (void *) DatumGetPointer(FunctionCall2(&prsobj->prsstart,
													 PointerGetDatum(buf),
													 Int32GetDatum(buflen)));

	LexizeInit(&ldata, cfg);

	do
	{
		if (type != 0)
		{
			type = DatumGetInt32(FunctionCall3(&(prsobj->prstoken),
											   PointerGetDatum(prsdata),
											   PointerGetDatum(&lemm),
											   PointerGetDatum(&lenlemm)));

			if (type > 0 && lenlemm >= MAXSTRLEN)
			{
#ifdef IGNORE_LONGLEXEME
				ereport(NOTICE,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
				continue;
#else
				ereport(ERROR,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
#endif
			}

			LexizeAddLemm(&ldata, type, lemm, lenlemm);
		}

		while ((norms = LexizeExec(&ldata, NULL)) != NULL)
		{
			TSLexeme   *ptr;
			ptr = norms;

			prs->pos++;			/* set pos */

			while (ptr->lexeme)
			{
				if (prs->curwords == prs->lenwords)
				{
					prs->lenwords *= 2;
					prs->words = (ParsedWord *) repalloc((void *) prs->words, prs->lenwords * sizeof(ParsedWord));
				}

				if (ptr->flags & TSL_ADDPOS)
					prs->pos++;
				prs->words[prs->curwords].len = strlen(ptr->lexeme);
				prs->words[prs->curwords].word = ptr->lexeme;
				prs->words[prs->curwords].nvariant = ptr->nvariant;
				prs->words[prs->curwords].flags = ptr->flags & TSL_PREFIX;
				prs->words[prs->curwords].alen = 0;
				prs->words[prs->curwords].pos.pos = LIMITPOS(prs->pos);
				ptr++;
				prs->curwords++;
			}
			pfree(norms);
		}
	} while (type != 0 || ldata.towork.head);

	FunctionCall1(&(prsobj->prsend), PointerGetDatum(prsdata));
}

/*
 * Headline framework
 */
static void
hladdword(HeadlineParsedText *prs, char *buf, int buflen, int type)
{
	while (prs->curwords >= prs->lenwords)
	{
		prs->lenwords *= 2;
		prs->words = (HeadlineWordEntry *) repalloc((void *) prs->words, prs->lenwords * sizeof(HeadlineWordEntry));
	}
	memset(&(prs->words[prs->curwords]), 0, sizeof(HeadlineWordEntry));
	prs->words[prs->curwords].type = (uint8) type;
	prs->words[prs->curwords].len = buflen;
	prs->words[prs->curwords].word = palloc(buflen);
	memcpy(prs->words[prs->curwords].word, buf, buflen);
	prs->curwords++;
}

static void
hlfinditem(HeadlineParsedText *prs, TSQuery query, int32 pos, char *buf, int buflen)
{
	int			i;
	QueryItem  *item = GETQUERY(query);
	HeadlineWordEntry *word;

	while (prs->curwords + query->size >= prs->lenwords)
	{
		prs->lenwords *= 2;
		prs->words = (HeadlineWordEntry *) repalloc((void *) prs->words, prs->lenwords * sizeof(HeadlineWordEntry));
	}

	word = &(prs->words[prs->curwords - 1]);
	word->pos = LIMITPOS(pos);
	for (i = 0; i < query->size; i++)
	{
		if (item->type == QI_VAL &&
			tsCompareString(GETOPERAND(query) + item->qoperand.distance, item->qoperand.length,
							buf, buflen, item->qoperand.prefix) == 0)
		{
			if (word->item)
			{
				memcpy(&(prs->words[prs->curwords]), word, sizeof(HeadlineWordEntry));
				prs->words[prs->curwords].item = &item->qoperand;
				prs->words[prs->curwords].repeated = 1;
				prs->curwords++;
			}
			else
				word->item = &item->qoperand;
		}
		item++;
	}
}

static void
addHLParsedLex(HeadlineParsedText *prs, TSQuery query, ParsedLex *lexs, TSLexeme *norms)
{
	ParsedLex  *tmplexs;
	TSLexeme   *ptr;
	int32		savedpos;

	while (lexs)
	{
		if (lexs->type > 0)
			hladdword(prs, lexs->lemm, lexs->lenlemm, lexs->type);

		ptr = norms;
		savedpos = prs->vectorpos;
		while (ptr && ptr->lexeme)
		{
			if (ptr->flags & TSL_ADDPOS)
				savedpos++;
			hlfinditem(prs, query, savedpos, ptr->lexeme, strlen(ptr->lexeme));
			ptr++;
		}

		tmplexs = lexs->next;
		pfree(lexs);
		lexs = tmplexs;
	}

	if (norms)
	{
		ptr = norms;
		while (ptr->lexeme)
		{
			if (ptr->flags & TSL_ADDPOS)
				prs->vectorpos++;
			pfree(ptr->lexeme);
			ptr++;
		}
		pfree(norms);
	}
}

void
hlparsetext(Oid cfgId, HeadlineParsedText *prs, TSQuery query, char *buf, int buflen)
{
	int			type = -1,
				lenlemm;
	char	   *lemm = NULL;
	LexizeData	ldata;
	TSLexeme   *norms;
	ParsedLex  *lexs;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	void	   *prsdata;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);

	prsdata = (void *) DatumGetPointer(FunctionCall2(&(prsobj->prsstart),
													 PointerGetDatum(buf),
													 Int32GetDatum(buflen)));

	LexizeInit(&ldata, cfg);

	do
	{
		if (type != 0)
		{
			type = DatumGetInt32(FunctionCall3(&(prsobj->prstoken),
											   PointerGetDatum(prsdata),
											   PointerGetDatum(&lemm),
											   PointerGetDatum(&lenlemm)));

			if (type > 0 && lenlemm >= MAXSTRLEN)
			{
#ifdef IGNORE_LONGLEXEME
				ereport(NOTICE,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
				continue;
#else
				ereport(ERROR,
						(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
						 errmsg("word is too long to be indexed"),
						 errdetail("Words longer than %d characters are ignored.",
								   MAXSTRLEN)));
#endif
			}

			LexizeAddLemm(&ldata, type, lemm, lenlemm);
		}

		do
		{
			if ((norms = LexizeExec(&ldata, &lexs)) != NULL)
			{
				prs->vectorpos++;
				addHLParsedLex(prs, query, lexs, norms);
			}
			else
				addHLParsedLex(prs, query, lexs, NULL);
		} while (norms);

	} while (type != 0 || ldata.towork.head);

	FunctionCall1(&(prsobj->prsend), PointerGetDatum(prsdata));
}

text *
generateHeadline(HeadlineParsedText *prs)
{
	text	   *out;
	char	   *ptr;
	int			len = 128;
	int			numfragments = 0;
	int16		infrag = 0;

	HeadlineWordEntry *wrd = prs->words;

	out = (text *) palloc(len);
	ptr = ((char *) out) + VARHDRSZ;

	while (wrd - prs->words < prs->curwords)
	{
		while (wrd->len + prs->stopsellen + prs->startsellen + prs->fragdelimlen + (ptr - ((char *) out)) >= len)
		{
			int			dist = ptr - ((char *) out);

			len *= 2;
			out = (text *) repalloc(out, len);
			ptr = ((char *) out) + dist;
		}

		if (wrd->in && !wrd->repeated)
		{
			if (!infrag)
			{

				/* start of a new fragment */
				infrag = 1;
				numfragments++;
				/* add a fragment delimiter if this is after the first one */
				if (numfragments > 1)
				{
					memcpy(ptr, prs->fragdelim, prs->fragdelimlen);
					ptr += prs->fragdelimlen;
				}

			}
			if (wrd->replace)
			{
				*ptr = ' ';
				ptr++;
			}
			else if (!wrd->skip)
			{
				if (wrd->selected)
				{
					memcpy(ptr, prs->startsel, prs->startsellen);
					ptr += prs->startsellen;
				}
				memcpy(ptr, wrd->word, wrd->len);
				ptr += wrd->len;
				if (wrd->selected)
				{
					memcpy(ptr, prs->stopsel, prs->stopsellen);
					ptr += prs->stopsellen;
				}
			}
		}
		else if (!wrd->repeated)
		{
			if (infrag)
				infrag = 0;
			pfree(wrd->word);
		}

		wrd++;
	}

	SET_VARSIZE(out, ptr - ((char *) out));
	return out;
}

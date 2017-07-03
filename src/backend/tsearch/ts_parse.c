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
	 * fields to store last variant to lexize (basically, thesaurus or similar
	 * to, which wants	several lexemes
	 */

	ParsedLex  *lastRes;
	TSLexeme   *tmpRes;
} LexizeData;

typedef struct
{
	Oid			dictId;
	LexizeData *ld;
	ParsedLex **correspondLexem;
} LexizeContext;

typedef struct
{
	int					len;
	LexizeContext	   *context;
	bool				restartProcessing;
} LexizeContextList;

static TSLexeme *LexizeExec(LexizeContextList *contextList);
static TSLexeme *LexizeExecDictionary(int dictId, LexizeContextList *contextList);
static TSLexeme *LexizeExecOperator(TSConfigCacheEntry *cfg, ParsedLex *curVal, 
		TSConfigurationOperatorDescriptor operator, LexizeContextList *contextList);

static void
LexizeInit(LexizeData *ld, TSConfigCacheEntry *cfg)
{
	ld->cfg = cfg;
	ld->curDictId = InvalidOid;
	ld->posDict = 0;
	ld->towork.head = ld->towork.tail = ld->curSub = NULL;
	ld->waste.head = ld->waste.tail = NULL;
	ld->lastRes = NULL;
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

	newpl->type = type;
	newpl->lemm = lemm;
	newpl->lenlemm = lenlemm;
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

static void
moveToWaste(LexizeData *ld, ParsedLex *stop)
{
	bool		go = true;

	while (ld->towork.head && go)
	{
		if (ld->towork.head == stop)
		{
			ld->curSub = stop->next;
			go = false;
		}
		RemoveHead(ld);
	}
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
	ld->lastRes = lex;
}

static void
ListParsedLexCopy(ListParsedLex *to, ListParsedLex *from)
{
	ParsedLex *node = from->head;
	ParsedLex *prevNewNode = NULL;

	to->head = to->tail = NULL;

	while (node)
	{
		ParsedLex *newnode = palloc0(sizeof(ParsedLex));

		newnode->type = node->type;
		newnode->lenlemm = node->lenlemm;
		newnode->lemm = palloc0(sizeof(char) * node->lenlemm);
		newnode->next = NULL;

		memcpy(newnode->lemm, node->lemm, sizeof(char) * node->lenlemm);
		if (prevNewNode)
			prevNewNode->next = newnode;

		if (to->head == NULL)
			to->head = newnode;
		prevNewNode = newnode;
		to->tail = newnode;
		node = node->next;
	}
}

static void
LexizeContextListAddContext(LexizeContextList *contextList, Oid dictId, LexizeData *ld, ParsedLex **correspondLexem)
{
	contextList->len++;

	if (contextList->context)
		contextList->context = repalloc(contextList->context, sizeof(LexizeData) * contextList->len);
	else
		contextList->context = palloc(sizeof(LexizeData) * contextList->len);

	contextList->context[contextList->len - 1].dictId = dictId;

	contextList->context[contextList->len - 1].ld = palloc0(sizeof(LexizeData));
	memcpy(contextList->context[contextList->len - 1].ld, ld, sizeof(LexizeData));
	ListParsedLexCopy(&contextList->context[contextList->len - 1].ld->towork, &ld->towork);
	ListParsedLexCopy(&contextList->context[contextList->len - 1].ld->waste, &ld->waste);

	contextList->context[contextList->len - 1].ld->tmpRes = ld->tmpRes;
	contextList->context[contextList->len - 1].ld->lastRes = ld->lastRes;
	ld->tmpRes = NULL;
	ld->lastRes = NULL;

	contextList->context[contextList->len - 1].correspondLexem = correspondLexem;
}

static void
LexizeContextListRemoveContext(LexizeContextList *contextList, Oid dictId)
{
	int i;
	for (i = 0; i < contextList->len; i++)
	{
		if (contextList->context[i].dictId == dictId)
		{
			if (contextList->context[i].ld)
				pfree(contextList->context[i].ld);
			if (contextList->context[i].correspondLexem)
				pfree(contextList->context[i].correspondLexem);
			memcpy(contextList->context + i, contextList->context + i + 1, sizeof(LexizeContext) * (contextList->len - i - 1));
			contextList->len--;
			// Shrink size of allocated memory
			contextList->context = repalloc(contextList->context, sizeof(LexizeContext) * contextList->len);
			return;
		}
	}
}

static LexizeContext *
LexizeContextListGetContext(LexizeContextList *contextList, Oid dictId)
{
	int i;
	for (i = 0; i < contextList->len; i++)
		if (contextList->context[i].dictId == dictId)
			return contextList->context + i;
	return NULL;
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

static TSLexeme *
LexizeExecOperatorThen(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator, LexizeContextList *contextList)
{
	ListDictionary			   *map = cfg->map + curVal->type;
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	TSLexeme				   *leftRes;
	TSLexeme				   *rightRes;
	TSLexeme				   *res;
	TSLexeme				  **thenRightRes;
	int						   *thenRightSizes;
	int							nvariant;
	int							i;
	int							resSize;
	int							leftSize;
	int							rightSize;

	leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], contextList)
		: LexizeExecDictionary(map->dictIds[operator.l_pos], contextList);

	resSize = 0;
	res = palloc0(sizeof(TSLexeme));
	leftSize = TSLexemeGetSize(leftRes);
	thenRightRes = palloc0(sizeof(TSLexeme*) * leftSize);
	thenRightSizes = palloc0(sizeof(int) * leftSize);

	/*
	 * Store right-side results in array of pointers, in order to
	 * allocate result TSLexeme array in one call without reallocations
	 * for each right-side result
	 */
	for (i = 0; (leftRes + i) != NULL && (leftRes + i)->lexeme; i++)
	{
		curVal->lemm = (leftRes + i)->lexeme;
		curVal->lenlemm = strlen((leftRes + i)->lexeme);
		thenRightRes[i] = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], contextList)
				: LexizeExecDictionary(map->dictIds[operator.r_pos], contextList);
		thenRightSizes[i] = TSLexemeGetSize(thenRightRes[i]);
		resSize += thenRightSizes[i];
	}

	res = palloc0(sizeof(TSLexeme) * (resSize + 1));
	rightSize = 0;
	nvariant = 0;
	for (i--; i >= 0; i--)
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
	pfree(thenRightSizes);
	pfree(thenRightRes);
	return res;
}

static TSLexeme *
LexizeExecOperatorOr(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator, LexizeContextList *contextList)
{
	ListDictionary			   *map = cfg->map + curVal->type;
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	TSLexeme				   *leftRes;
	TSLexeme				   *rightRes;
	TSLexeme				   *res;

	leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], contextList)
		: LexizeExecDictionary(map->dictIds[operator.l_pos], contextList);

	if (!contextList->restartProcessing &&
			(leftRes != NULL ||
			 (operator.l_is_operator == 0 &&
			  LexizeContextListGetContext(contextList, map->dictIds[operator.l_pos]) != NULL)))
	{
		res = leftRes;
	}
	else
	{
		/*
		 * The dictionary mark the processing to restart.
		 * In this case, we should re-execute left operand to process curVal
		 * without saved context.
		 * There are three sources of lexem:
		 *   1) first-left side execution
		 *   2) second-left side execution
		 *   3) right-side execution
		 * ride-side results used only if second left-side is NULL and there
		 * is not new context for the left side.
		 */
		if (contextList->restartProcessing)
		{
			contextList->restartProcessing = false;
			rightRes = leftRes;
			leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], contextList)
				: LexizeExecDictionary(map->dictIds[operator.l_pos], contextList);
			res = TSLexemeCombine(rightRes, leftRes);
			if (leftRes)
				pfree(leftRes);
			if (rightRes)
				pfree(rightRes);

			if (leftRes == NULL && !(operator.l_is_operator == 0 && LexizeContextListGetContext(contextList, map->dictIds[operator.l_pos]) != NULL))
			{
				leftRes = res;
				rightRes = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], contextList)
					: LexizeExecDictionary(map->dictIds[operator.r_pos], contextList);
				if (contextList->restartProcessing)
				{
					res = TSLexemeCombine(leftRes, rightRes);
					if (leftRes)
						pfree(leftRes);
					if (rightRes)
						pfree(rightRes);
					leftRes = res;
					rightRes = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], contextList)
						: LexizeExecDictionary(map->dictIds[operator.r_pos], contextList);
				}

				if (leftRes && rightRes)
					rightRes->flags |= TSL_ADDPOS;
				res = TSLexemeCombine(leftRes, rightRes);
				if (leftRes)
					pfree(leftRes);
				if (rightRes)
					pfree(rightRes);
			}
		}
		else
		{
			res = rightRes = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], contextList)
				: LexizeExecDictionary(map->dictIds[operator.r_pos], contextList);
			if (contextList->restartProcessing)
			{
				leftRes = res;
				rightRes = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], contextList)
					: LexizeExecDictionary(map->dictIds[operator.r_pos], contextList);
				if (rightRes)
					rightRes->flags |= TSL_ADDPOS;
				res = TSLexemeCombine(leftRes, rightRes);
				if (leftRes)
					pfree(leftRes);
				if (rightRes)
					pfree(rightRes);
			}
		}
	}
	return res;
}

static TSLexeme *
LexizeExecOperatorAnd(TSConfigCacheEntry *cfg, ParsedLex *curVal,
		TSConfigurationOperatorDescriptor operator, LexizeContextList *contextList)
{
	ListDictionary			   *map = cfg->map + curVal->type;
	ListDictionaryOperators	   *operators = cfg->operators + curVal->type;
	TSLexeme				   *leftRes;
	TSLexeme				   *rightRes;
	TSLexeme				   *res;

	leftRes = operator.l_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.l_pos], contextList)
		: LexizeExecDictionary(map->dictIds[operator.l_pos], contextList);

	rightRes = operator.r_is_operator ? LexizeExecOperator(cfg, curVal, operators->operators[operator.r_pos], contextList)
		: LexizeExecDictionary(map->dictIds[operator.r_pos], contextList);

	res = TSLexemeCombine(leftRes, rightRes);
	return res;
}

static TSLexeme *
LexizeExecOperator(TSConfigCacheEntry *cfg, ParsedLex *curVal, 
		TSConfigurationOperatorDescriptor operator, LexizeContextList *contextList)
{
	TSLexeme				   *res;

	Assert(operator.presented == 1);

	switch (operator.oper)
	{
		case DICTPIPE_OP_THEN:
			res = LexizeExecOperatorThen(cfg, curVal, operator, contextList);
			break;
		case DICTPIPE_OP_OR:
			res = LexizeExecOperatorOr(cfg, curVal, operator, contextList);
			break;
		case DICTPIPE_OP_AND:
			res = LexizeExecOperatorAnd(cfg, curVal, operator, contextList);
			break;
		default:
			res = NULL;
			ereport(ERROR,
					(errcode(ERRCODE_DATA_CORRUPTED),
					 errmsg("Operator entry in TSConfiguration is corrupted"),
					 errdetail("Operator id %d is invalid.",
							   operator.oper)));
			break;
	}
	return res;
}

static TSLexeme *
LexizeExecDictionary(int dictId, LexizeContextList *contextList)
{
	ParsedLex				   *curVal;
	LexizeData				   *ld;
	ParsedLex				  **correspondLexem;
	TSDictionaryCacheEntry	   *dict;
	TSLexeme				   *res = NULL;
	LexizeContext			   *context;
	int							i;

	context = LexizeContextListGetContext(contextList, dictId);
	dict = lookup_ts_dictionary_cache(dictId);

	if (context == NULL) /* Standard mode */
	{
		context = LexizeContextListGetContext(contextList, InvalidOid);
		Assert(context != NULL);

		ld = context->ld;
		correspondLexem = context->correspondLexem;

		curVal = ld->towork.head;
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
			 * dictionary wants next word, so setup and store current
			 * position and go to multiword mode
			 */
			LexizeContext	   *context;

			LexizeContextListAddContext(contextList, dictId, ld, correspondLexem);
			context = LexizeContextListGetContext(contextList, dictId);

			ld = context->ld;
			correspondLexem = context->correspondLexem;

			ld->curDictId = DatumGetObjectId(dictId);
			RemoveHead(ld);
//			setCorrLex(ld, correspondLexem);
			if (res)
				setNewTmpRes(ld, curVal, res);
			return NULL;
		}
		return res;
	}
	else
	{
		/* Process multi-input dictionary with saved state */
		ListDictionary	   *map;

		ld = context->ld;
		correspondLexem = context->correspondLexem;
		curVal = ld->towork.head;

		while (curVal)
		{
			map = ld->cfg->map + curVal->type;
			if (curVal->type != 0 && (curVal->type >= ld->cfg->lenmap || map->len == 0))
			{
				/* skip this type of lexeme */
				RemoveHead(ld);
//				setCorrLex(ld, correspondLexem);
			}
			else
			{
				break;
			}
			curVal = ld->towork.head;
		}


		if (curVal->type != 0)
		{
			bool		dictExists = false;

			/*
			 * We should be sure that current type of lexeme is recognized
			 * by our dictionary: we just check is it exist in list of
			 * dictionaries ?
			 */
			for (i = 0; i < map->len && !dictExists; i++)
				if (ld->curDictId == DatumGetObjectId(map->dictIds[i]))
					dictExists = true;

			if (!dictExists)
			{
				/*
				 * Dictionary can't work with current type of lexeme,
				 * return to basic mode
				 */
				LexizeContextListRemoveContext(contextList, ld->curDictId);
				contextList->restartProcessing = true;
				return NULL;
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
				setNewTmpRes(ld, curVal, res);
			RemoveHead(ld);
			return NULL;
		}

		if (res || ld->tmpRes)
		{
			/*
			 * Dictionary normalizes lexemes, so we remove from stack all
			 * used lexemes, return to basic mode and redo end of stack
			 * (if it exists)
			 */
			if (!res)
			{
				res = ld->tmpRes;
				contextList->restartProcessing = true;
			}

			/* reset to initial state */
			LexizeContextListRemoveContext(contextList, ld->curDictId);
			return res;
		}

		/*
		 * Dict don't want next lexem and didn't recognize anything, redo
		 * from ld->towork.head
		 */
		LexizeContextListRemoveContext(contextList, ld->curDictId);
		return res;
	}
	return res;
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
					int		nvariantCountL = 1;
					int		nvariantCountR = 1;
					int		nvariantOverlap = 1;
					int		j;

					for (j = curLexIndex + 1; j < lexemeSize; j++)
						if (lexeme[curLexIndex].nvariant == lexeme[j].nvariant)
							nvariantCountL++;
					for (j = i + 1; j < lexemeSize; j++)
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

static TSLexeme *
LexizeExec(LexizeContextList *contextList)
{
	ListDictionary			   *map;
	ListDictionaryOperators	   *operators;
	TSLexeme				   *res = NULL;
	ParsedLex				   *curVal;
	LexizeData				   *ld;
	ParsedLex				  **correspondLexem;
	int							i;

	ld = contextList->context[0].ld; // Get default LexizeData
	correspondLexem = contextList->context[0].correspondLexem;
	if (ld->towork.head == NULL)
	{
		setCorrLex(ld, correspondLexem);
		return NULL;
	}

	curVal = ld->towork.head;
	while (curVal)
	{
		map = ld->cfg->map + curVal->type;
		operators = ld->cfg->operators + curVal->type;

		if (curVal->type != 0 && (curVal->type >= ld->cfg->lenmap || map->len == 0 || operators->len == 0))
		{
			/* skip this type of lexeme */
			RemoveHead(ld);
			setCorrLex(ld, correspondLexem);
			return NULL;
		}

		if (curVal->type == 0) // End of the input, finish processing of multi-input dictionaries
		{
			TSLexeme *tmpRes;

			for (i = 1; i < contextList->len; i++)
			{
				tmpRes = LexizeExecDictionary(contextList->context[i].dictId, contextList);
				if (tmpRes != NULL)
				{
					TSLexeme *combinedRes = TSLexemeCombine(res, tmpRes);
					if (res)
						pfree(res);
					pfree(tmpRes);
					res = combinedRes;
				}
				i = 0; // Possibly the contextList has been changed during LexizeExecDictionary execution, restart in the loop
			}
			res = TSLexemeRemoveDuplications(res);
			return res;
		}

		if (map->len == 1) // There are no operators, just single dictionary
		{
			res = LexizeExecDictionary(map->dictIds[0], contextList);
		}
		else // There is a dictionary pipe expression tree, start from top operator
		{
			Assert(operators->len != 0);
			res = LexizeExecOperator(ld->cfg, curVal, operators->operators[0], contextList);
		}

		for (i = 1; i < contextList->len; i++)
		{
			if (contextList->context[i].ld->towork.head != NULL)
			{
				TSLexeme *tmpRes;
				TSLexeme *combinedRes;

				contextList->context[i].ld->towork.head->type = 0;
				tmpRes = LexizeExecDictionary(contextList->context[i].dictId, contextList);

				if (tmpRes)
					res->flags |= TSL_ADDPOS;

				combinedRes = TSLexemeCombine(tmpRes, res);
				if (res)
					pfree(res);
				if (tmpRes)
					pfree(tmpRes);
				res = combinedRes;
				i = 0; // Possibly the contextList has been changed during LexizeExecDictionary execution, restart in the loop
			}
		}

		RemoveHead(ld);
		curVal = ld->towork.head;
	}

	res = TSLexemeRemoveDuplications(res);
	setCorrLex(ld, correspondLexem);
	return res;
}

static TSLexeme *
LexizeExecOld(LexizeData *ld, ParsedLex **correspondLexem)
{
	int			i;
	ListDictionary *map;
	TSDictionaryCacheEntry *dict;
	TSLexeme   *res;

	if (ld->curDictId == InvalidOid)
	{
		/*
		 * usual mode: dictionary wants only one word, but we should keep in
		 * mind that we should go through all stack
		 */

		while (ld->towork.head)
		{
			ParsedLex  *curVal = ld->towork.head;
			char	   *curValLemm = curVal->lemm;
			int			curValLenLemm = curVal->lenlemm;

			map = ld->cfg->map + curVal->type;

			if (curVal->type == 0 || curVal->type >= ld->cfg->lenmap || map->len == 0)
			{
				/* skip this type of lexeme */
				RemoveHead(ld);
				continue;
			}

			for (i = ld->posDict; i < map->len; i++)
			{
				dict = lookup_ts_dictionary_cache(map->dictIds[i]);

				ld->dictState.isend = ld->dictState.getnext = false;
				ld->dictState.private_state = NULL;
				res = (TSLexeme *) DatumGetPointer(FunctionCall4(
																 &(dict->lexize),
																 PointerGetDatum(dict->dictData),
																 PointerGetDatum(curValLemm),
																 Int32GetDatum(curValLenLemm),
																 PointerGetDatum(&ld->dictState)
																 ));

				if (ld->dictState.getnext)
				{
					/*
					 * dictionary wants next word, so setup and store current
					 * position and go to multiword mode
					 */

					ld->curDictId = DatumGetObjectId(map->dictIds[i]);
					ld->posDict = i + 1;
					ld->curSub = curVal->next;
					if (res)
						setNewTmpRes(ld, curVal, res);
					return LexizeExecOld(ld, correspondLexem);
				}

				if (!res)		/* dictionary doesn't know this lexeme */
					continue;

				if (res->flags & TSL_FILTER)
				{
					curValLemm = res->lexeme;
					curValLenLemm = strlen(res->lexeme);
					continue;
				}

				RemoveHead(ld);
				setCorrLex(ld, correspondLexem);
				return res;
			}

			RemoveHead(ld);
			setCorrLex(ld, correspondLexem);
		}
	}
	else
	{							/* curDictId is valid */
		dict = lookup_ts_dictionary_cache(ld->curDictId);

		/*
		 * Dictionary ld->curDictId asks  us about following words
		 */

		while (ld->curSub)
		{
			ParsedLex  *curVal = ld->curSub;

			map = ld->cfg->map + curVal->type;

			if (curVal->type != 0)
			{
				bool		dictExists = false;

				if (curVal->type >= ld->cfg->lenmap || map->len == 0)
				{
					/* skip this type of lexeme */
					ld->curSub = curVal->next;
					continue;
				}

				/*
				 * We should be sure that current type of lexeme is recognized
				 * by our dictionary: we just check is it exist in list of
				 * dictionaries ?
				 */
				for (i = 0; i < map->len && !dictExists; i++)
					if (ld->curDictId == DatumGetObjectId(map->dictIds[i]))
						dictExists = true;

				if (!dictExists)
				{
					/*
					 * Dictionary can't work with current tpe of lexeme,
					 * return to basic mode and redo all stored lexemes
					 */
					ld->curDictId = InvalidOid;
					return LexizeExecOld(ld, correspondLexem);
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
				ld->curSub = curVal->next;
				if (res)
					setNewTmpRes(ld, curVal, res);
				continue;
			}

			if (res || ld->tmpRes)
			{
				/*
				 * Dictionary normalizes lexemes, so we remove from stack all
				 * used lexemes, return to basic mode and redo end of stack
				 * (if it exists)
				 */
				if (res)
				{
					moveToWaste(ld, ld->curSub);
				}
				else
				{
					res = ld->tmpRes;
					moveToWaste(ld, ld->lastRes);
				}

				/* reset to initial state */
				ld->curDictId = InvalidOid;
				ld->posDict = 0;
				ld->lastRes = NULL;
				ld->tmpRes = NULL;
				setCorrLex(ld, correspondLexem);
				return res;
			}

			/*
			 * Dict don't want next lexem and didn't recognize anything, redo
			 * from ld->towork.head
			 */
			ld->curDictId = InvalidOid;
			return LexizeExecOld(ld, correspondLexem);
		}
	}

	setCorrLex(ld, correspondLexem);
	return NULL;
}

/*
 * Parse string and lexize words.
 *
 * prs will be filled in.
 */
void
parsetext(Oid cfgId, ParsedText *prs, char *buf, int buflen)
{
	int			type,
				lenlemm;
	char	   *lemm = NULL;
	LexizeData	ldata;
	TSLexeme   *norms;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	void	   *prsdata;
	LexizeContextList *contextList = palloc(sizeof(LexizeContextList));
	int			i;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);
	contextList->restartProcessing = false;
	contextList->len = 1;
	contextList->context = palloc(sizeof(LexizeContext));
	contextList->context[0].correspondLexem = NULL;
	contextList->context[0].dictId = InvalidOid;
	contextList->context[0].ld = &ldata;

	prsdata = (void *) DatumGetPointer(FunctionCall2(&prsobj->prsstart,
													 PointerGetDatum(buf),
													 Int32GetDatum(buflen)));

	LexizeInit(&ldata, cfg);

	do
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

		for (i = 0; i < contextList->len; i++)
		{
			LexizeAddLemm(contextList->context[i].ld, type, lemm, lenlemm);
		}
//		LexizeAddLemm(&ldata, type, lemm, lenlemm);

		while ((norms = LexizeExec(contextList)) != NULL)
		{
			TSLexeme   *ptr = norms;

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
	} while (type > 0);

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
	int			type,
				lenlemm;
	char	   *lemm = NULL;
	LexizeData	ldata;
	TSLexeme   *norms;
	ParsedLex  *lexs;
	TSConfigCacheEntry *cfg;
	TSParserCacheEntry *prsobj;
	LexizeContextList *contextList = palloc0(sizeof(LexizeContextList));
	void	   *prsdata;

	cfg = lookup_ts_config_cache(cfgId);
	prsobj = lookup_ts_parser_cache(cfg->prsId);
	contextList->restartProcessing = false;
	contextList->len = 1;
	contextList->context = palloc(sizeof(LexizeContext));
	contextList->context[0].correspondLexem = &lexs;
	contextList->context[0].dictId = InvalidOid;
	contextList->context[0].ld = &ldata;

	prsdata = (void *) DatumGetPointer(FunctionCall2(&(prsobj->prsstart),
													 PointerGetDatum(buf),
													 Int32GetDatum(buflen)));

	LexizeInit(&ldata, cfg);

	do
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

		do
		{
			if ((norms = LexizeExec(contextList)) != NULL)
			{
				prs->vectorpos++;
				addHLParsedLex(prs, query, lexs, norms);
			}
			else
				addHLParsedLex(prs, query, lexs, NULL);
		} while (norms);

	} while (type > 0);

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

#include "postgres.h"

#include "access/spgist.h"
#include "access/stratnum.h"
#include "catalog/pg_type.h"
#include "utils/fmgrprotos.h"
#include "ltree.h"

typedef struct traValue {
	ltree_level*	llevel;
} traValue;

static Datum
formTextDatum(const char *data, int datalen)
{
	char	   *p;

	p = (char *) palloc(datalen + VARHDRSZ);

	if (datalen + VARHDRSZ_SHORT <= VARATT_SHORT_MAX)
	{
		SET_VARSIZE_SHORT(p, datalen + VARHDRSZ_SHORT);
		if (datalen)
			memcpy(p + VARHDRSZ_SHORT, data, datalen);
	}
	else
	{
		SET_VARSIZE(p, datalen + VARHDRSZ);
		memcpy(p + VARHDRSZ, data, datalen);
	}

	return PointerGetDatum(p);
}

PG_FUNCTION_INFO_V1(spg_ltree_config);

Datum
spg_ltree_config(PG_FUNCTION_ARGS)
{
	spgConfigOut *cfg = (spgConfigOut *) PG_GETARG_POINTER(1);

	cfg->prefixType = VOIDOID;
	cfg->labelType = TEXTOID;
	cfg->canReturnData = false;
	cfg->longValuesOK = false;

	PG_RETURN_VOID();
}

static bool
searchLabel(Datum *nodeLabels, int nNodes, ltree_level *inptr, int *i)
{
	int	StopLow = 0,
		StopHigh = nNodes;

	while (StopLow < StopHigh)
	{
		int	StopMiddle = (StopLow + StopHigh) >> 1;
		text	*middle = DatumGetTextPP(nodeLabels[StopMiddle]);
		int cmp;

		if (VARSIZE_ANY_EXHDR(middle) == 0)
		{
			if (inptr == NULL)
				cmp = 0;
			else
				cmp = -1;
		}
		else if (inptr == NULL)
			cmp = 1;
		else
		{
			cmp = memcmp(VARDATA_ANY(middle), inptr->name,
						 Min(VARSIZE_ANY_EXHDR(middle), inptr->len));

			if (cmp == 0)
			{
				if (VARSIZE_ANY_EXHDR(middle) > inptr->len)
					cmp = 1;
				else if (VARSIZE_ANY_EXHDR(middle) < inptr->len)
					cmp = -1;
			}
		}

		if (cmp < 0)
			StopLow = StopMiddle + 1;
		else if (cmp > 0)
			StopHigh = StopMiddle;
		else
		{
			*i = StopMiddle;
			return true;
		}
	}

	*i = StopHigh;
	return false;
}

PG_FUNCTION_INFO_V1(spg_ltree_choose);

Datum
spg_ltree_choose(PG_FUNCTION_ARGS)
{
	spgChooseIn *in = (spgChooseIn *) PG_GETARG_POINTER(0);
	spgChooseOut *out = (spgChooseOut *) PG_GETARG_POINTER(1);
	ltree		*inLtree = DatumGetLtreeP(in->datum);
	ltree_level	*inptr = LTREE_FIRST(inLtree);
	int			i;

	if (inLtree->numlevel == 0 || in->level >= inLtree->numlevel)
		inptr = NULL;
	else
		for(i=0; i<in->level; i++)
			inptr = LEVEL_NEXT(inptr);

	if (searchLabel(in->nodeLabels, in->nNodes, inptr, &i))
	{
		out->resultType = spgMatchNode;
		out->result.matchNode.nodeN = i;
		if (inptr != NULL && in->level+1 < inLtree->numlevel)
		{
			out->result.matchNode.levelAdd = 1;
			out->result.matchNode.restDatum = PointerGetDatum(
						inner_subltree(inLtree, in->level+1, inLtree->numlevel)
					);
		}
		else
		{
			out->result.matchNode.levelAdd = 0;
			out->result.matchNode.restDatum = PointerGetDatum(
						inner_subltree(inLtree, 0, 0)
					);
		}
	}
	else if (in->allTheSame)
	{
		out->resultType = spgMatchNode;
		out->result.matchNode.levelAdd = 0;
		if (inptr != NULL && in->level < inLtree->numlevel)
			out->result.matchNode.restDatum = PointerGetDatum(
						inner_subltree(inLtree, in->level, inLtree->numlevel)
					);
		else
			out->result.matchNode.restDatum = PointerGetDatum(
						inner_subltree(inLtree, 0, 0)
					);
	}
	else
	{
		out->resultType = spgAddNode;
		if (inptr)
			out->result.addNode.nodeLabel = PointerGetDatum(
				formTextDatum(inptr->name, inptr->len)
			);
		else
			out->result.addNode.nodeLabel = PointerGetDatum(
				formTextDatum(NULL, 0)
			);

		out->result.addNode.nodeN = i;
	}

	PG_RETURN_VOID();
}

typedef struct spgNodePtr
{
	Datum	d;
	int		i;
	text	*label;
} spgNodePtr;

static int
cmpNodePtr(const void *a, const void *b)
{
	const spgNodePtr *aa = (const spgNodePtr *) a;
	const spgNodePtr *bb = (const spgNodePtr *) b;
	int cmp;

	cmp = memcmp(VARDATA_ANY(aa->label),
				 VARDATA_ANY(bb->label),
				 Min(VARSIZE_ANY_EXHDR(aa->label),
					 VARSIZE_ANY_EXHDR(bb->label)));

	if (cmp == 0)
	{
		if (VARSIZE_ANY_EXHDR(aa->label) > VARSIZE_ANY_EXHDR(bb->label))
			cmp = 1;
		else if (VARSIZE_ANY_EXHDR(aa->label) < VARSIZE_ANY_EXHDR(bb->label))
			cmp = -1;
	}

	return cmp;
}

PG_FUNCTION_INFO_V1(spg_ltree_picksplit);

Datum
spg_ltree_picksplit(PG_FUNCTION_ARGS)
{
	spgPickSplitIn *in = (spgPickSplitIn *) PG_GETARG_POINTER(0);
	spgPickSplitOut *out = (spgPickSplitOut *) PG_GETARG_POINTER(1);
	int				i;
	spgNodePtr		*nodes;

	out->hasPrefix = false;

	nodes = (spgNodePtr *) palloc(sizeof(spgNodePtr) * in->nTuples);

	for (i = 0; i < in->nTuples; i++)
	{
		ltree	*li = DatumGetLtreeP(in->datums[i]);

		if (li->numlevel > 0)
			nodes[i].label = DatumGetTextPP(
					formTextDatum(LTREE_FIRST(li)->name,
								  LTREE_FIRST(li)->len)
			);
		else
			nodes[i].label = DatumGetTextPP(formTextDatum(NULL, 0));
		nodes[i].i = i;
		nodes[i].d = in->datums[i];
	}

	qsort(nodes, in->nTuples, sizeof(*nodes), cmpNodePtr);

	out->nNodes = 0;
	out->nodeLabels = (Datum *) palloc(sizeof(Datum) * in->nTuples);
	out->mapTuplesToNodes = (int *) palloc(sizeof(int) * in->nTuples);
	out->leafTupleDatums = (Datum *) palloc(sizeof(Datum) * in->nTuples);

	for (i = 0; i < in->nTuples; i++)
	{
		ltree   *li = DatumGetLtreeP(nodes[i].d);

		if (i == 0 || cmpNodePtr(nodes+i, nodes+i-1))
		{
			out->nodeLabels[out->nNodes] = PointerGetDatum(nodes[i].label);
			out->nNodes++;
		}

		if (li->numlevel > 1)
			out->leafTupleDatums[nodes[i].i] = PointerGetDatum(
						inner_subltree(li, 1, li->numlevel)
					);
		else if (li->numlevel == 0)
			out->leafTupleDatums[nodes[i].i] = PointerGetDatum(li);
		else
			out->leafTupleDatums[nodes[i].i] = PointerGetDatum(
						inner_subltree(li, 0, 0)
					);
		out->mapTuplesToNodes[nodes[i].i] = out->nNodes - 1;
	}

	PG_RETURN_VOID();
}

static void*
makeTraValue(MemoryContext	cntx, traValue *ltl)
{
	traValue	*r = ltl;

	if (ltl)
	{
		MemoryContext	oldCtx = MemoryContextSwitchTo(cntx);

		r = palloc(sizeof(*r));
		r->llevel = LEVEL_NEXT(ltl->llevel);

		MemoryContextSwitchTo(oldCtx);
	}

	return r;
}

PG_FUNCTION_INFO_V1(spg_ltree_inner_consistent);

Datum
spg_ltree_inner_consistent(PG_FUNCTION_ARGS)
{
	spgInnerConsistentIn *in = (spgInnerConsistentIn *) PG_GETARG_POINTER(0);
	spgInnerConsistentOut *out = (spgInnerConsistentOut *) PG_GETARG_POINTER(1);
	int i;
	traValue	*ltl, ltls;

	if (in->level == 0)
	{
		if (in->nkeys!=1)
			elog(ERROR, "Doesn't support multiple scan keys");

		ltls.llevel = LTREE_FIRST(DatumGetLtreeP(in->scankeys->sk_argument));
		in->traversalValue = &ltls;
	}

	ltl = in->traversalValue;

	if (in->level >= DatumGetLtreeP(in->scankeys->sk_argument)->numlevel)
		ltl = NULL;

	out->nodeNumbers = (int *) palloc(sizeof(int) * in->nNodes);
	out->levelAdds = (int *) palloc(sizeof(int) * in->nNodes);
	out->traversalValues = (void **) palloc0(sizeof(void *) * in->nNodes);
	out->nNodes = 0;

	if (in->allTheSame)
	{
		text	*lbl = DatumGetTextPP(in->nodeLabels[0]);

		if ((VARSIZE_ANY_EXHDR(lbl) == 0 && ltl == NULL) ||
			(VARSIZE_ANY_EXHDR(lbl) > 0 && ltl &&
			 VARSIZE_ANY_EXHDR(lbl) == ltl->llevel->len &&
			 memcmp(VARDATA_ANY(lbl), ltl->llevel->name, ltl->llevel->len) == 0))
		{
			out->nNodes = in->nNodes;

			for (i = 0; i < in->nNodes; i++)
			{
				out->nodeNumbers[i] = i;
				out->levelAdds[i] = 1;
				out->traversalValues[i] =
					makeTraValue(in->traversalMemoryContext, ltl);
			}
		}

		PG_RETURN_VOID();
	}

	switch(in->scankeys->sk_strategy)
	{
		case 11:
			if (ltl == NULL)
			{
				for(i=0; i<in->nNodes; i++)
				{
					out->nodeNumbers[out->nNodes] = i;
					out->levelAdds[out->nNodes] = 0;
					out->nNodes++;
				}
				break;
			}
			/* FALLTHROUGH */
		case 10:
			if (ltl == NULL &&
				in->level > DatumGetLtreeP(in->scankeys->sk_argument)->numlevel)
				break;
			if (ltl != NULL && in->scankeys->sk_strategy == 10 &&
				searchLabel(in->nodeLabels, in->nNodes, NULL, &i))
			{
				/* add empty */
				out->nodeNumbers[out->nNodes] = i;
				out->levelAdds[out->nNodes] = 1;
				out->traversalValues[out->nNodes] =
					makeTraValue(in->traversalMemoryContext, ltl);
				out->nNodes++;
			}
			/* FALLTHROUGH */
		case BTEqualStrategyNumber:
			if (searchLabel(in->nodeLabels, in->nNodes, ltl ? ltl->llevel : NULL, &i))
			{
				out->nodeNumbers[out->nNodes] = i;
				out->levelAdds[out->nNodes] = (ltl) ? 1 : 0;
				out->traversalValues[out->nNodes] =
					makeTraValue(in->traversalMemoryContext, ltl);
				out->nNodes++;
			}
			break;
		default:
			elog(ERROR, "unknown strategy %d", in->scankeys->sk_strategy);
	}

	PG_RETURN_VOID();
}

static int
ltree_level_cmp(ltree_level *al, int an, ltree *b, bool *notaprefix)
{
	ltree_level *bl = LTREE_FIRST(b);
	int		 bn = b->numlevel;

	*notaprefix = true;

	while (an > 0 && bn > 0)
	{
		int res;

		res = memcmp(al->name, bl->name, Min(al->len, bl->len));
		if (res || al->len != bl->len)
		{
			*notaprefix = false;
			return 0;
		}

		an--;
		bn--;
		al = LEVEL_NEXT(al);
		bl = LEVEL_NEXT(bl);
	}

	if (an == 0 && bn == 0)
		return 0;

	return (an == 0) ? -1 : 1;
}

PG_FUNCTION_INFO_V1(spg_ltree_leaf_consistent);

Datum
spg_ltree_leaf_consistent(PG_FUNCTION_ARGS)
{
	spgLeafConsistentIn *in = (spgLeafConsistentIn *) PG_GETARG_POINTER(0);
	spgLeafConsistentOut *out = (spgLeafConsistentOut *) PG_GETARG_POINTER(1);
	ltree	*leafValue;
	traValue	*ltl, ltls;
	bool	res = false,
			isprefix = false;
	ltree	*keyValue;

	out->recheck = false;

	leafValue = DatumGetLtreeP(in->leafDatum);
	keyValue = DatumGetLtreeP(in->scankeys->sk_argument);

	if (in->level == 0)
	{
		if (in->nkeys!=1)
			elog(ERROR, "Doesn't support multiple scan keys");

		ltls.llevel = LTREE_FIRST(DatumGetLtreeP(in->scankeys->sk_argument));
		in->traversalValue = &ltls;
	}

	ltl = in->traversalValue;

	if (in->level >= keyValue->numlevel)
		ltl = NULL;

	switch(in->scankeys->sk_strategy)
	{
		case 11:
			res = (ltl == NULL ||
				   (ltree_level_cmp(ltl->llevel, keyValue->numlevel - in->level,
									leafValue, &isprefix) <= 0 && isprefix));
			break;
		case BTEqualStrategyNumber:
			if (ltl == NULL)
				res = (leafValue->numlevel == 0);
			else
				res = (ltree_level_cmp(ltl->llevel, keyValue->numlevel - in->level,
									   leafValue,&isprefix) == 0 && isprefix);
			break;
		case 10:
			res = (leafValue->numlevel == 0 ||
				   (ltree_level_cmp(ltl ? ltl->llevel : NULL, keyValue->numlevel - in->level,
								   leafValue, &isprefix)>=0 && isprefix));
			break;
		default:
			elog(ERROR, "unknown strategy %d", in->scankeys->sk_strategy);
	}

	PG_RETURN_BOOL(res);
}

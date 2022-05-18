#include "postgres.h"

#include "access/gin.h"
#include "access/stratnum.h"
#include "utils/fmgrprotos.h"
#include "ltree.h"

PG_FUNCTION_INFO_V1(ginltree_extract);

extern Datum
ltree_out(PG_FUNCTION_ARGS);
	//	elog(NOTICE, "%s", DatumGetCString(DirectFunctionCall1(ltree_out,
	//														  PointerGetDatum(l))));

Datum
ginltree_extract(PG_FUNCTION_ARGS)
{
	ltree	*a = PG_GETARG_LTREE_P_COPY(0);
	int32	*nkeys = (int32 *) PG_GETARG_POINTER(1);
	bool	**nullFlags = (bool **) PG_GETARG_POINTER(2);
	Datum	*elems = palloc(sizeof(*elems));

	*nkeys=1;
	*nullFlags=NULL;
	elems[0]=PointerGetDatum(a);

	PG_RETURN_POINTER(elems);
}

PG_FUNCTION_INFO_V1(ginltree_queryextract);

Datum
ginltree_queryextract(PG_FUNCTION_ARGS)
{
	int32	*nentries = (int32 *) PG_GETARG_POINTER(1);
	StrategyNumber strategy = PG_GETARG_UINT16(2);
	bool	**partialmatch = (bool **) PG_GETARG_POINTER(3);
	int32	*searchMode = (int32 *) PG_GETARG_POINTER(6);
	Datum	*res = NULL;

	*searchMode = GIN_SEARCH_MODE_DEFAULT;

	if (strategy == 1)
	{
		PG_RETURN_DATUM(DirectFunctionCall7(ginqueryarrayextract,
											PG_GETARG_DATUM(0),
											PG_GETARG_DATUM(1),
											PG_GETARG_DATUM(2),
											PG_GETARG_DATUM(3),
											PG_GETARG_DATUM(4),
											PG_GETARG_DATUM(5),
											PG_GETARG_DATUM(6)));
	}
	else if (strategy == 11 ||
		strategy == BTEqualStrategyNumber)
	{
		ltree	*q = PG_GETARG_LTREE_P_COPY(0);

		res = palloc(sizeof(*res));
		*partialmatch = (bool *) palloc(sizeof(bool));
		res[0] = PointerGetDatum(q);
		*nentries = 1;
		(*partialmatch)[0] = (strategy == BTEqualStrategyNumber) ? false : true;
	}
	else if (strategy == 10)
	{
		int i;
		ltree_level	*ptr;
		ltree	*q = PG_GETARG_LTREE_P(0);

		res = palloc(sizeof(*res) * (q->numlevel+1));
		*nentries = q->numlevel+1;

		ptr = LTREE_FIRST(q);
		for(i=0; i<q->numlevel+1; i++)
		{
			ltree	*r = palloc(VARSIZE(q));
			int32	bytelen = ((char*)ptr) - ((char*)q);

			memcpy(r, q, bytelen);

			r->numlevel = i;
			SET_VARSIZE(r, bytelen);
			res[i] = PointerGetDatum(r);

			ptr = LEVEL_NEXT(ptr);
		}
	}
	else if (strategy == 12 || strategy == 13)
	{
		lquery *q = PG_GETARG_LQUERY_P(0);
		int i;
		ltree	*l = palloc(VARSIZE(q));
		ltree_level	*ptr_ltree;
		lquery_level	*ptr_ltquery;
		lquery_variant	*ptr_variant;

		l->numlevel=0;
		ptr_ltree = LTREE_FIRST(l);
		ptr_ltquery = LQUERY_FIRST(q);

		for(i=0;i<q->numlevel;i++)
		{
			if (ptr_ltquery->numvar != 1)
				break;
			if (ptr_ltquery->flag & LQL_NOT)
				break;

			ptr_variant = LQL_FIRST(ptr_ltquery);

			if ((ptr_variant->flag & (LVAR_SUBLEXEME | LVAR_INCASE | LVAR_ANYEND)) != 0)
				break;

			ptr_ltree->len = ptr_variant->len;
			memcpy(ptr_ltree->name, ptr_variant->name, ptr_variant->len);

			l->numlevel++;

			ptr_ltree = LEVEL_NEXT(ptr_ltree);
			ptr_ltquery = LQL_NEXT(ptr_ltquery);
		}

		SET_VARSIZE(l, ((char*)ptr_ltree) - ((char*)l));

		res = palloc(sizeof(*res));
		*partialmatch = (bool *) palloc(sizeof(bool));
		res[0] = PointerGetDatum(l);
		*nentries = 1;
		(*partialmatch)[0] = (l->numlevel == q->numlevel) ? false : true;
	}
	else
		elog(ERROR, "Unknown strategy %d", strategy);

	PG_RETURN_POINTER(res);
}

static int
ltree_is_prefix(const ltree *a, const ltree *b)
{
	ltree_level *al = LTREE_FIRST(a);
	ltree_level *bl = LTREE_FIRST(b);
	int			an = a->numlevel;
	int			bn = b->numlevel;

	if (bn < an)
		return 1;

	while (an > 0 && bn > 0)
	{
		int	res;

		if (al->len != bl->len)
			return 1;

		if ((res = memcmp(al->name, bl->name, Min(al->len, bl->len))) != 0)
			return 1;

		an--;
		bn--;
		al = LEVEL_NEXT(al);
		bl = LEVEL_NEXT(bl);
	}

	return 0;
}

PG_FUNCTION_INFO_V1(ginltree_cmp_prefix);

Datum
ginltree_cmp_prefix(PG_FUNCTION_ARGS)
{
	ltree	*a = PG_GETARG_LTREE_P(0);
	ltree	*b = PG_GETARG_LTREE_P(1);
	int		cmp;

	cmp = ltree_is_prefix(a, b);

	PG_FREE_IF_COPY(a, 0);
	PG_FREE_IF_COPY(b, 1);
	PG_RETURN_INT32(cmp);
}

PG_FUNCTION_INFO_V1(ginltree_consistent);

Datum
ginltree_consistent(PG_FUNCTION_ARGS)
{
	bool			*recheck = (bool *) PG_GETARG_POINTER(5);
	StrategyNumber strategy = PG_GETARG_UINT16(1);

	*recheck = false;

	if (strategy == 12 || strategy == 13)
		*recheck = true;

	PG_RETURN_BOOL(true);
}





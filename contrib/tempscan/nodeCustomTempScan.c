/* -------------------------------------------------------------------------
 *
 * nodeCustomTempScan.c
 *		Implements strategy which allows to build and execute partial paths for
 *		a query which contains tempoorary table scans.
 *
 * Copyright (c) 2017-2024, Postgres Professional
 *
 * IDENTIFICATION
 *		contrib/tempscan/nodeCustomTempScan.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "nodes/extensible.h"
#include "optimizer/clauses.h"
#include "optimizer/cost.h"
#include "optimizer/optimizer.h"
#include "optimizer/pathnode.h"
#include "optimizer/paths.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"

PG_MODULE_MAGIC;

#define MODULENAME	"tempscan"
#define NODENAME	"nodeCustomTempScan"

/* By analogy with Append */
#define TEMPSCAN_CPU_COST_MULTIPLIER	(0.5)

static Plan *create_partial_tempscan_plan(PlannerInfo *root,
										  RelOptInfo *rel,
										  CustomPath *best_path,
										  List *tlist,
										  List *scan_clauses,
										  List *custom_plans);
static Node *create_tempscan_state(CustomScan *cscan);
static void BeginTempScan(CustomScanState *node, EState *estate, int eflags);
static TupleTableSlot *ExecTempScan(CustomScanState *node);
static void EndTempScan(CustomScanState *node);
static void ReScanTempScan(CustomScanState *node);
static Size EstimateDSMTempScan(CustomScanState *node, ParallelContext *pcxt);

static CustomPathMethods path_methods =
{
	.CustomName = NODENAME,
	.PlanCustomPath = create_partial_tempscan_plan,
	.ReparameterizeCustomPathByChild = NULL
};

static CustomScanMethods plan_methods =
{
	.CustomName = NODENAME,
	.CreateCustomScanState = create_tempscan_state
};

static CustomExecMethods exec_methods =
{
	.CustomName = NODENAME,

	.BeginCustomScan = BeginTempScan,
	.ExecCustomScan = ExecTempScan,
	.EndCustomScan = EndTempScan,
	.ReScanCustomScan = ReScanTempScan,
	.MarkPosCustomScan = NULL,
	.RestrPosCustomScan = NULL,
	.EstimateDSMCustomScan = EstimateDSMTempScan,
	.InitializeDSMCustomScan = NULL,
	.ReInitializeDSMCustomScan = NULL,
	.InitializeWorkerCustomScan = NULL,
	.ShutdownCustomScan = NULL,
	.ExplainCustomScan = NULL
};

static set_rel_pathlist_hook_type set_rel_pathlist_hook_next = NULL;

static bool tempscan_enable = false;

void _PG_init(void);

/*
 * The input path shouldn't be a part of the relation pathlist.
 */
static CustomPath *
create_partial_tempscan_path(PlannerInfo *root, RelOptInfo *rel,
							 Path *path)
{
	CustomPath *cpath;
	Path	   *pathnode;

	cpath = makeNode(CustomPath);
	pathnode = &cpath->path;

	pathnode->pathtype = T_CustomScan;
	pathnode->parent = rel;
	pathnode->pathtarget = rel->reltarget;
	pathnode->rows = path->rows; /* Don't use rel->rows! Remember semantics of this field in the parallel case */
	pathnode->param_info = path->param_info;

	pathnode->parallel_safe = true;
	pathnode->parallel_aware = false;
	pathnode->parallel_workers = path->parallel_workers;

	pathnode->startup_cost = path->startup_cost;
	pathnode->total_cost = path->total_cost;

	/*
	 * Although TempScan does not do any selection or projection, it's not free;
	 * add a small per-tuple overhead.
	 */
	pathnode->total_cost +=
					cpu_tuple_cost * TEMPSCAN_CPU_COST_MULTIPLIER * path->rows;

	cpath->custom_paths = list_make1(path);
	cpath->custom_private = NIL;
	cpath->custom_restrictinfo = NIL;
	cpath->methods = &path_methods;

	return cpath;
}

static Plan *
create_partial_tempscan_plan(PlannerInfo *root, RelOptInfo *rel,
							 CustomPath *best_path, List *tlist,
							 List *scan_clauses, List *custom_plans)
{
	CustomScan *cscan = makeNode(CustomScan);

	Assert(list_length(custom_plans) == 1);
	Assert(best_path->path.parallel_safe = true);


	cscan->scan.plan.targetlist = cscan->custom_scan_tlist = tlist;
	cscan->scan.scanrelid = 0;
	cscan->custom_exprs = NIL;
	cscan->custom_plans = custom_plans;
	cscan->methods = &plan_methods;
	cscan->flags = best_path->flags;
	cscan->custom_private = best_path->custom_private;

	return &cscan->scan.plan;
}

static Node *
create_tempscan_state(CustomScan *cscan)
{
	CustomScanState	   *cstate = makeNode(CustomScanState);

	cstate->methods = &exec_methods;

	return (Node *) cstate;
}

static void
BeginTempScan(CustomScanState *node, EState *estate, int eflags)
{
	CustomScan  *cscan = (CustomScan *) node->ss.ps.plan;
	Plan		*subplan;
	PlanState   *pstate;

	Assert(list_length(cscan->custom_plans) == 1);

	subplan = (Plan *) linitial(cscan->custom_plans);
	pstate = ExecInitNode(subplan, estate, eflags);
	node->custom_ps = lappend(node->custom_ps, (void *) pstate);
}

static TupleTableSlot *
ExecTempScan(CustomScanState *node)
{
	Assert(list_length(node->custom_ps) == 1);

	return ExecProcNode((PlanState *) linitial(node->custom_ps));
}

static void
EndTempScan(CustomScanState *node)
{
	ExecClearTuple(node->ss.ss_ScanTupleSlot);
	ExecEndNode((PlanState *) linitial(node->custom_ps));
}

static void
ReScanTempScan(CustomScanState *node)
{
	PlanState *child;

	ExecClearTuple(node->ss.ps.ps_ResultTupleSlot);

	child = (PlanState *) linitial(node->custom_ps);

	if (node->ss.ps.chgParam != NULL)
		UpdateChangedParamSet(child, node->ss.ps.chgParam);

	ExecReScan(child);
}

/*
 * Try to add partial paths to the scan of a temporary table.
 *
 * In contrast to the hook on a JOIN paths creation, here we already at the end
 * of paths creation procedure, right before insertion of a gather node.
 * So, we can discover pathlist and choose any base path we can and want to use
 * in parallel scan.
 *
 * TODO: add inner strategy for temp table scan (parallel_workers == 0,
 * parallel_safe == true). Right now it looks a bit more difficult to implement.
 */
static void
try_partial_tempscan(PlannerInfo *root, RelOptInfo *rel, Index rti,
					 RangeTblEntry *rte)
{
	ListCell   *lc;
	List	   *parallel_safe_lst = NIL;
	List	   *tmplst = rel->pathlist;

	/*
	 * Some extension intercept this hook earlier. Allow it to do a work
	 * before us.
	 */
	if (set_rel_pathlist_hook_next)
		(*set_rel_pathlist_hook_next)(root, rel, rti, rte);

	if (!tempscan_enable || rel->consider_parallel)
		return;

	if (rte->rtekind != RTE_RELATION ||
		get_rel_persistence(rte->relid) != RELPERSISTENCE_TEMP)
		return;

	if (!is_parallel_safe(root, (Node *) rel->baserestrictinfo) ||
		!is_parallel_safe(root, (Node *) rel->reltarget->exprs))
		return;

	/* Enable parallel safe paths generation for this relation */
	Assert(rel->partial_pathlist == NIL);
	rel->consider_parallel = true;

	/*
	 * Now we have a problem:
	 * should generate parallel safe paths. But they will have the same cost as
	 * previously added non-parallel ones and, being safe, will definitely crowd
	 * out non-safe ones.
	 * So, we need a HACK: add new safe paths with cost of custom node.
	 */

	rel->pathlist = NIL;

	/*
	 * Build possibly parallel paths other temporary table
	 */
	add_path(rel, create_seqscan_path(root, rel, NULL, 0));
	create_index_paths(root, rel);
	create_tidscan_paths(root, rel);

	/*
	 * Dangerous zone. But we assume it is strictly local. What about extension
	 * which could call ours and may have desire to add some partial paths after
	 * us?
	 */

	list_free(rel->partial_pathlist);
	rel->partial_pathlist = NIL;

	/*
	 * Set guard over each parallel_safe path
	 */
	parallel_safe_lst = rel->pathlist;
	rel->pathlist = tmplst;
	foreach(lc, parallel_safe_lst)
	{
		Path   *path = lfirst(lc);

		if (!path->parallel_safe)
			continue;

		add_path(rel, (Path *) create_partial_tempscan_path(root, rel, path));
	}

	list_free(parallel_safe_lst);
}

void
_PG_init(void)
{
	DefineCustomBoolVariable("tempscan.enable",
							 "Enable feature of the parallel temporary table scan.",
							 "Right now no any other purpose except debugging",
							 &tempscan_enable,
							 false,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL
	);

	set_rel_pathlist_hook_next = set_rel_pathlist_hook;
	set_rel_pathlist_hook = try_partial_tempscan;

	RegisterCustomScanMethods(&plan_methods);

	MarkGUCPrefixReserved(MODULENAME);
}

/* *****************************************************************************
 *
 * Parallel transport stuff
 *
 **************************************************************************** */

/* copy from execParallel.c */
#define PARALLEL_TUPLE_QUEUE_SIZE		65536

static Size
EstimateDSMTempScan(CustomScanState *node, ParallelContext *pcxt)
{
	Size size;

	size = mul_size(PARALLEL_TUPLE_QUEUE_SIZE, pcxt->nworkers);
	return size;
}
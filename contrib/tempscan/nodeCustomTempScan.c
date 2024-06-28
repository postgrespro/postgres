/* -------------------------------------------------------------------------
 *
 * nodeCustomTempScan.c
 *		Implements strategy which allows to build and execute partial paths for
 *		a query which contains tempoorary table scans.
 *
 * Specifics of this node:
 * 		So far as this node lies inside the parallel worker and master plan, it
 * 		would be too brave think we know who first will execute Begin, Exec or
 * 		End routines. So, it must initialize tuple queue earlier than Gather do.
 *
 * 		Another thing - nodeParallelTempScan on master must wait for
 * 		initialization of all the workers - we must send each tuple to their
 * 		queues and therefore, initialize receivers on the worker side.
 * 		XXX: for parallel temp scan does it would be needed?
 *
 *
 * Copyright (c) 2017-2024, Postgres Professional
 *
 * IDENTIFICATION
 *		contrib/tempscan/nodeCustomTempScan.c
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "executor/tqueue.h"
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
static void InitializeDSMTempScan(CustomScanState *node, ParallelContext *pcxt,
								  void *coordinate);
static void ReInitializeDSMTempScan(CustomScanState *node,
									ParallelContext *pcxt,
									void *coordinate);
static void InitializeWorkerTempScan(CustomScanState *node, shm_toc *toc,
									 void *coordinate);
static void ShutdownTempScan(CustomScanState *node);
static shm_mq_handle **ExecParallelSetupTupleQueues(int nworkers,
													char *tqueuespace,
													dsm_segment *seg);

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
	.InitializeDSMCustomScan = InitializeDSMTempScan,
	.ReInitializeDSMCustomScan = ReInitializeDSMTempScan,
	.InitializeWorkerCustomScan = InitializeWorkerTempScan,
	.ShutdownCustomScan = ShutdownTempScan,
	.ExplainCustomScan = NULL
};

static set_rel_pathlist_hook_type set_rel_pathlist_hook_next = NULL;

static bool tempscan_enable = true;
static bool tempscan_force = false;

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
	pathnode->param_info = NULL; /* Can't use parameterisation, at least for now */

	pathnode->parallel_safe = true;
	pathnode->parallel_workers = path->parallel_workers;
	pathnode->parallel_aware = pathnode->parallel_workers > 0;

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
	cscan->custom_private = list_make1(makeInteger(best_path->path.parallel_workers));

	return &cscan->scan.plan;
}

typedef struct SharedTempScanInfo
{
	int			nworkers_launched;
	dsm_handle	handle;
} SharedTempScanInfo;

typedef struct ParallelTempScanState
{
	CustomScanState		node;

	bool				initialized;
	int					nworkers; /* workers planned. Needed to know how much resources to free */
	DestReceiver	  **receiver; /* Must be NULL for workers */
	shm_mq_handle	  **tqueue;
	ParallelContext	   *pcxt;
	SharedTempScanInfo *shared;

	TupleQueueReader   *reader;
	bool				parallelMode;
} ParallelTempScanState;

static Node *
create_tempscan_state(CustomScan *cscan)
{
	ParallelTempScanState  *ts = palloc0(sizeof(ParallelTempScanState));
	CustomScanState		   *cstate = (CustomScanState *) ts;
	int path_workers = linitial_node(Integer, cscan->custom_private)->ival;

	Assert(list_length(cscan->custom_plans) == 1);

	cstate->ss.ps.type = T_CustomScanState;
	cstate->methods = &exec_methods;
	ts->parallelMode = (path_workers > 0);

	/*
	 * Setup slotOps manually. Although we just put incoming tuple to the result
	 * slot, we must remember that the tqueueReceiveSlot in tqueue.c may need
	 * another kind of tuple to be effective.
	 */
	cstate->slotOps = &TTSOpsMinimalTuple;

	ts->receiver = NULL;
	ts->tqueue = NULL;
	ts->initialized = false;

	ts->shared = NULL;

	if (!IsParallelWorker())
	{
		ts->reader = NULL;
	}
	else
	{
		list_free(cscan->custom_plans);
		cscan->custom_plans = NIL;
	}

	return (Node *) cstate;
}

/*
 * Remember the case when it works without any parallel workers at all
 */
static void
BeginTempScan(CustomScanState *node, EState *estate, int eflags)
{
	CustomScan  *cscan = (CustomScan *) node->ss.ps.plan;
	ParallelTempScanState *ts = (ParallelTempScanState *) node;
	Plan		*subplan;
	PlanState   *pstate;

	if (!(eflags & EXEC_FLAG_EXPLAIN_ONLY))
		/*
		 * Just a hack to provide consistent EXPLAIN and custom DSM
		 * initialisation
		 */
		cscan->scan.plan.parallel_aware = true;

	Assert(ts->receiver == NULL && !ts->initialized &&
		   ts->shared == NULL);
	/*
	 * Different logic for master process (sender) and worker (receiver):
	 * Master should initiate underlying scan node. Worker must ignore it at all
	 */
	if (!IsParallelWorker())
	{
		subplan = (Plan *) linitial(cscan->custom_plans);
		pstate = ExecInitNode(subplan, estate, eflags);
		node->custom_ps = lappend(node->custom_ps, (void *) pstate);
	}
	else
	{
		Assert(list_length(node->custom_ps) == 0);
	}
}

static TupleTableSlot *
ExecTempScan(CustomScanState *node)
{
	ParallelTempScanState  *ts = (ParallelTempScanState *) node;
	TupleTableSlot		   *result = ts->node.ss.ss_ScanTupleSlot;
	TupleTableSlot *slot;
	bool			should_free;
	MinimalTuple	tup;
	int				i;

	/*
	 * HACK. At this point Custom DSM already initialised and we can switch off
	 * this parameter.
	 */
	if (ts->pcxt->nworkers_launched == 0)
		ts->node.ss.ps.plan->parallel_aware = false;

	if (IsParallelWorker())
	{
		MinimalTuple	tup;
		bool			done;

		/* Parallel worker should receive something from the tqueue */
		tup = TupleQueueReaderNext(ts->reader, false, &done);

		if (done)
		{
			Assert(tup == NULL);
			return NULL;
		}

		/* TODO: should free ? */
		ExecStoreMinimalTuple(tup, result, false);
		result->tts_ops->copyslot(result, result);
		return result;
	}

	Assert(list_length(node->custom_ps) == 1);

	if (!ts->initialized)
	{
		/*
		 * Save number of workers because we will need it on later
		 * stages of the execution.
		 */
		ts->shared->nworkers_launched = ts->pcxt->nworkers_launched;
		ts->initialized = true;
	}

	slot = ExecProcNode((PlanState *) linitial(node->custom_ps));
	if (ts->receiver == NULL)
		return slot;

	if (TupIsNull(slot))
	{
		/* Parallel workers case */
		for (i = 0; i < ts->shared->nworkers_launched; i++)
		{
			ts->receiver[i]->rDestroy(ts->receiver[i]);
			ts->receiver[i] = NULL;
			ts->tqueue[i] = NULL;
		}
		pfree(ts->receiver);
		ts->receiver = NULL;
		/* The end of the table is achieved, Return empty tuple to all */
		return NULL;
	}

	if (!ts->parallelMode)
	{
		/* Prepare mimimal tuple to send all workers and upstream locally. */
		tup = ExecFetchSlotMinimalTuple(slot, &should_free);
		ExecStoreMinimalTuple(tup, result, should_free);

		/* Send the same tuple to each of worker. Don't forget myself */
		for (i = 0; i < ts->shared->nworkers_launched; ++i)
		{
			bool ret;

			ret = ts->receiver[i]->receiveSlot(result, ts->receiver[i]);
			Assert(ret);
		}
		return result;
	}
	else
	{
		int nworkers = ts->pcxt->nworkers_launched;
		/* Overwise we should tuple only to one of the workers */

		typedef struct TQueueDestReceiver
		{
			DestReceiver pub;			/* public fields */
			shm_mq_handle *queue;		/* shm_mq to send to */
		} TQueueDestReceiver;

		TQueueDestReceiver *rec;

		while (nworkers > 0)
		{
			/* Prepare mimimal tuple */
			tup = ExecFetchSlotMinimalTuple(slot, &should_free);
			ExecStoreMinimalTuple(tup, result, should_free);

			for (i = 0; i < nworkers; i++)
			{
				rec = (TQueueDestReceiver *) ts->receiver[i];
				result = shm_mq_send(tqueue->queue, tuple->t_len, tuple, false, false);
						(void) WaitLatch(MyLatch,
						 WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
						 (nap.tv_sec * 1000L) + (nap.tv_usec / 1000L),
						 WAIT_EVENT_AUTOVACUUM_MAIN);
			}
		}
	}
}

static void
EndTempScan(CustomScanState *node)
{
	ParallelTempScanState  *ts = (ParallelTempScanState *) node;

	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	if (!IsParallelWorker())
	{
		/* Do it only for the master process */
		ExecEndNode((PlanState *) linitial(node->custom_ps));

		/* Can happen if not all tuples needed */
		if (ts->receiver != NULL)
		{
			int i;

			for (i = 0; i < ts->nworkers; ++i)
			{
				ts->receiver[i]->rDestroy(ts->receiver[i]);
			}
		}
	}
	else
	{
		DestroyTupleQueueReader(ts->reader);
	}
}

static void
ReScanTempScan(CustomScanState *node)
{
	ParallelTempScanState  *ts = (ParallelTempScanState *) node;

	if (ts->initialized)
		elog(PANIC, "Parallel TempScan feature Doesn't support any sort of rescanning");

	if (IsParallelWorker())
		return;

	Assert(list_length(ts->node.custom_ps) == 1);
	ExecReScan(linitial(ts->node.custom_ps));
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

	if (!tempscan_enable || rel->consider_parallel || rte->inh)
		return;

	if (rte->rtekind != RTE_RELATION || rte->relkind != RELKIND_RELATION ||
		rel->reloptkind != RELOPT_BASEREL ||
		get_rel_persistence(rte->relid) != RELPERSISTENCE_TEMP ||
		root->query_level > 1)
		return;

	if (!is_parallel_safe(root, (Node *) rel->baserestrictinfo) ||
		!is_parallel_safe(root, (Node *) rel->reltarget->exprs))
		return;

	foreach(lc, rel->reltarget->exprs)
	{
		Expr *expr = lfirst(lc);

		if (IsA(expr, Var) && ((Var *)expr)->varno == ROWID_VAR)
			return;
	}

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
	add_path(rel, create_seqscan_path(root, rel, rel->lateral_relids, 0));
	create_index_paths(root, rel);
	create_tidscan_paths(root, rel);

	if (rel->consider_parallel && rel->lateral_relids == NULL)
	{
		int			parallel_workers;

	parallel_workers = compute_parallel_worker(rel, rel->pages, -1,
											   max_parallel_workers_per_gather);

	/* If any limit was set to zero, the user doesn't want a parallel scan. */
	if (parallel_workers <= 0)
		return;

	/* Add an unordered partial path based on a parallel sequential scan. */
	add_partial_path(rel, create_seqscan_path(root, rel, NULL, parallel_workers));
	}

	/*
	 * Dangerous zone. But we assume it is strictly local. What about extension
	 * which could call ours and may have desire to add some partial paths after
	 * us?
	 */

//	list_free(rel->partial_pathlist);
//	rel->partial_pathlist = NIL;

	/*
	 * Set guard over each parallel_safe path
	 */
	parallel_safe_lst = rel->pathlist;
	rel->pathlist = tmplst;
	foreach(lc, parallel_safe_lst)
	{
		Path   *path = lfirst(lc);
		Path   *cpath;

		if (!path->parallel_safe || path->param_info != NULL)
			continue;


		path->rows = clamp_row_est(path->rows / 3.);
		cpath = (Path *) create_partial_tempscan_path(root, rel, path);

		if (tempscan_force)
			path->total_cost = clamp_row_est(path->total_cost / disable_cost);

		/*
		 * Need materialisation here. Do the absence of internal parameters and
		 * lateral references guarantees we don't need to change any parameters
		 * on a ReScan?
		 */
		add_path(rel, (Path *) cpath
						/*create_material_path(cpath->parent, (Path *) cpath)*/);
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
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL
	);

	DefineCustomBoolVariable("tempscan.force",
							 NULL,
							 NULL,
							 &tempscan_force,
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
 * The model is simple enough: utilise tqueue module to establish separate shmem
 * queue connection between master process and each of workers.
 * Each tuple has fetched from temporary table we must push into each queue and
 * return it in locally too.
 *
 * This approach has some pro and cons but enough to demonstrate proposed
 * technique.
 *
 **************************************************************************** */

/* copy from execParallel.c */
#define PARALLEL_TUPLE_QUEUE_SIZE		65536
#define PARALLEL_KEY_TUPLE_QUEUE		UINT64CONST(0xE000000000000005)

static Size
EstimateDSMTempScan(CustomScanState *node, ParallelContext *pcxt)
{
	Size size = 0;

	size = add_size(size, sizeof(SharedTempScanInfo));
	return size;
}

/*
 * It sets up the response queues for backend workers to return tuples
 * to the main backend and start the workers.
 */
static shm_mq_handle **
ExecParallelSetupTupleQueues(int nworkers, char *tqueuespace, dsm_segment *seg)
{
	shm_mq_handle **responseq;
	int			i;

	/* Skip this if no workers. */
	if (nworkers == 0)
		return NULL;

	/* Allocate memory for shared memory queue handles. */
	responseq = (shm_mq_handle **) palloc(nworkers * sizeof(shm_mq_handle *));

	/* Create the queues. */
	for (i = 0; i < nworkers; ++i)
	{
		shm_mq	   *mq;

		mq = shm_mq_create(tqueuespace +
						   ((Size) i) * PARALLEL_TUPLE_QUEUE_SIZE,
						   (Size) PARALLEL_TUPLE_QUEUE_SIZE);

		/* Master process will send tuples to all workers */
		shm_mq_set_sender(mq, MyProc);
		responseq[i] = shm_mq_attach(mq, seg, NULL);
	}

	/* Return array of handles. */
	return responseq;
}

/*
 * Master creates shared memory queues - one separate queue for each worker.
 * Also, it should create DSM segment underlying this transport.
 */
static void
InitializeDSMTempScan(CustomScanState *node, ParallelContext *pcxt,
					  void *coordinate)
{
	ParallelTempScanState  *ts = (ParallelTempScanState *) node;
	dsm_segment			   *seg;

	seg = dsm_create(PARALLEL_TUPLE_QUEUE_SIZE * pcxt->nworkers,
					 DSM_CREATE_NULL_IF_MAXSEGMENTS);
	Assert(seg != NULL); /* Don't process this case so far */

	ts->pcxt = pcxt;

	/* Save shared data for common usage in parallel workers */
	ts->shared = (SharedTempScanInfo *) coordinate;
	ts->shared->handle = dsm_segment_handle(seg);
	ts->nworkers = pcxt->nworkers;

	/*
	 * We can't initialise queues to workers here because not sure about real
	 * number of workers will be launched (depends on the number of free slots
	 * for background workers - see max_worker_processes).
	 */

	/*
	 * Initialise receivers here.
	 * We don't do it earlier because real number of launched workers
	 * will be known only after the Gather node launch them.
	 * Anyway, in the case of any troubles we can initialise them
	 * earlier and just not use the tail of them during the execution.
	 */
	if (ts->shared && ts->nworkers > 0)
	{
		int				i;
		dsm_segment	   *seg = dsm_find_mapping(ts->shared->handle);

		ts->tqueue =
				ExecParallelSetupTupleQueues(ts->nworkers,
											 (char *) dsm_segment_address(seg),
											 seg);

		ts->receiver = palloc(ts->nworkers * sizeof(DestReceiver *));
		for (i = 0; i < ts->nworkers; i++)
		{
			ts->receiver[i] = CreateTupleQueueDestReceiver(ts->tqueue[i]);
		}
	}
	else
		elog(WARNING, "Workers do not needed");
}

static void
ReInitializeDSMTempScan(CustomScanState *node, ParallelContext *pcxt,
						void *coordinate)
{
	/* TODO */
	Assert(0);
}

static void
InitializeWorkerTempScan(CustomScanState *node, shm_toc *toc,
						 void *coordinate)
{
	ParallelTempScanState  *ts = (ParallelTempScanState *) node;
	shm_mq				   *mq;
	dsm_segment			   *seg;
	char				   *ptr;

	ts->shared = (SharedTempScanInfo *) coordinate;
	seg = dsm_attach(ts->shared->handle);
	ptr = dsm_segment_address(seg);
	mq = (shm_mq *) (ptr + ParallelWorkerNumber * PARALLEL_TUPLE_QUEUE_SIZE);

	/* Set myself as a receiver of tuples */
	shm_mq_set_receiver(mq, MyProc);

	ts->reader = CreateTupleQueueReader(shm_mq_attach(mq, seg, NULL));
	ts->initialized = true;
}

static void
ShutdownTempScan(CustomScanState *node)
{
	ParallelTempScanState  *ts = (ParallelTempScanState *) node;

	if (ts->shared)
		dsm_detach(dsm_find_mapping(ts->shared->handle));
}

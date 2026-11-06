# SecPatch-DAG Project Status

Last updated: 2026-11-06

Phase 5C: PostgreSQL integrity and test coverage are complete. The headless core remains database-independent.

The demo-ready React dashboard is now connected to the persisted API workflow.
It supports explicit demo setup, project/environment selection, asset
registration, inventory and OSV fixture uploads, dependency graph review,
CP-SAT or precedence-greedy optimization, proposed plan review, and historical
analysis retrieval.

**PROJECT STATUS: READY FOR ACADEMIC DEMONSTRATION**

## Phase 5 implementation

- Added SQLAlchemy 2.x infrastructure under `infrastructure/database/`.
- Added an explicit Alembic initial migration at `migrations/versions/0001_initial.py`.
- Added environment-based `DATABASE_URL` configuration and `PERSISTENCE_ENABLED` API opt-in.
- Added relational tables for projects, environments, assets, packages, installed inventory, package dependencies, vulnerabilities, remediation candidates, analysis runs, patch actions, patch-action prerequisites, patch plans, and plan actions.
- Analysis-run-specific patch actions preserve historical duration, benefit, priority, mandatory, and prerequisite estimates.
- Composite foreign keys enforce that both sides of a patch-action prerequisite belong to the same analysis run.
- Installed inventory uses a non-null `version_key`; multiple installed versions are allowed while duplicate asset/package/version records are rejected.
- Composite `(environment_id, project_id)` foreign-key validation ensures an analysis run cannot combine an environment with a different project.
- JSONB is used for source metadata and immutable input/result snapshots; relational foreign keys remain authoritative for domain relationships.
- Added application persistence services and project/environment API creation endpoints. Existing plan endpoints remain usable without persistence.
- Added repository classes for projects, environments, assets, inventory, vulnerabilities/candidates, and analysis-run retrieval.
- Added project/environment update endpoints and asset CRUD endpoints.
- Added inventory import and asset inventory retrieval endpoints.
- Added normalized OSV vulnerability and remediation-candidate persistence with source/id deduplication.
- Added persisted analysis execution from stored candidates and explicitly supplied operational estimates.
- Added normalized `patch_actions`, `patch_action_prerequisites`, `patch_plans`, and `patch_plan_actions` persistence.
- Added historical analysis listing and complete result retrieval, including immutable snapshots and normalized schedule offsets.
- Persistence is opt-in so the JSON CLI and headless workflows do not require a database.
- FastAPI CORS is restricted to local Vite development origins.
- Inventory retrieval includes package name and ecosystem details for the dashboard.

## Phase 5 files

Created:

- `infrastructure/database/base.py`
- `infrastructure/database/models.py`
- `infrastructure/database/session.py`
- `application/persistence.py`
- `alembic.ini`
- `migrations/env.py`
- `migrations/script.py.mako`
- `migrations/versions/0001_initial.py`
- `tests/test_database.py`
- `tests/postgresql_support.py`
- `tests/test_postgresql_integration.py`
- `tests/test_postgresql_api.py`
- `infrastructure/database/repositories.py`
- `frontend/src/main.tsx`
- `frontend/src/styles.css`
- `frontend/src/vite-env.d.ts`

Changed:

- `pyproject.toml`
- `requirements.txt`
- `.env.example`
- `backend/main.py`
- `application/persistence.py`
- `README.md`
- `PROJECT_STATUS.md`
- `frontend/src/main.tsx`
- `frontend/src/styles.css`

## Phase 5 verification

- Complete pytest suite: `58 passed, 0 failed`.
- Alembic offline SQL generation: passed; migration emits PostgreSQL DDL.
- Core CLI with CP-SAT and JSON assertion: passed; `OPTIMAL`, valid plan, objective `105`.
- Offline ingestion CLI with JSON assertion: passed; objective `90`, valid plan.
- API import and `/api/v1/health` endpoint: passed.
- SQLite persistence tests: passed for CRUD/service mapping, multiple inventory versions, normalized patch-plan persistence, historical retrieval, and relationship constraints supported by SQLite.
- Dedicated PostgreSQL integration and API tests: `6 passed, 0 failed` against PostgreSQL 18.6 in `secpatch_test`.
- PostgreSQL coverage includes JSONB round trips, versioned inventory and duplicate prevention, OSV deduplication, remediation candidates, same-run prerequisite enforcement, patch-plan/run consistency, historical immutability, rollback, and persisted FastAPI workflows.
- The dedicated suite loads the root `.env`, requires `current_database() = 'secpatch_test'`, and skips only with an explicit reason when PostgreSQL is unavailable; it never falls back to SQLite.
- Alembic current revision: `0001_initial (head)`.
- Frontend production build: passed with `npm run build`.
- API workflow tests after dashboard integration: `3 passed, 0 failed`.

## Phase 5 known limitations and risks

1. The legacy `/api/v1/plans` path remains in-memory unless `PERSISTENCE_ENABLED=true`; `/api/v1/persisted-plans` explicitly executes from persisted candidates.
2. Timestamp defaults use application/database UTC defaults, but migration does not yet add an automatic `updated_at` trigger.
3. Authentication, authorization, scenarios, multi-tenancy, and frontend persistence are intentionally deferred.

## Next recommended phase

Consider adding authentication, authorization, scenarios, and multi-tenancy.
Frontend persistence is already implemented through the PostgreSQL-backed API.

Phase 4: Dependency Graph Intelligence is implemented and verified. Phase 5C
adds live PostgreSQL persistence, API workflows, and a connected demo dashboard.

## Implemented functionality

- Preserved the headless core and existing Phase 1, Phase 2, and Phase 3 contracts.
- Package dependency direction remains `dependent_package -> prerequisite_package`.
- Package dependencies remain separate from patch-action prerequisites.
- Extended `core/graph.py` into a reusable graph analysis module with:
  - Tarjan SCC detection
  - self-loop and multi-node cycle detection
  - condensation graph construction
  - prerequisite-first Kahn topological ordering
  - deterministic BFS prerequisite traversal
  - deterministic DFS prerequisite traversal
  - direct prerequisites
  - transitive prerequisites
  - dependents
  - dependency depth
  - blocked-package impact from cyclic SCCs
- Existing unresolved-cycle behavior is preserved and strengthened:
  - cyclic packages are blocked
  - dependent packages impacted by cyclic packages are also blocked
  - action prerequisites remain independent and continue to be enforced by CP-SAT
- Added `graph_contract(...)`, a frontend-independent JSON structure containing:
  - package nodes and node types
  - typed directed package-dependency edges
  - component IDs
  - cyclic and blocked status
  - dependency depth
  - direct/transitive prerequisites
  - dependents
  - cycle explanations
  - valid ordering and analysis summaries
- Integrated the graph contract into `run_analysis` under `graph.dependency_analysis`.
- Critical-path analysis was intentionally not added. Package edges have no durations, while patch durations belong to separate patch actions; a package-level critical path would be semantically misleading.

## Files created or changed

Created:

- `tests/test_graph_intelligence.py`

Changed:

- `core/graph.py`
- `core/engine.py`
- `README.md`
- `PROJECT_STATUS.md`

No Docker, deployment, or automatic patch-installation work was added.

## Verification

Executed:

```text
.\.venv\Scripts\python.exe -m pytest -q
58 passed, 1 warning

.\.venv\Scripts\python.exe -m pytest -q tests\test_postgresql_integration.py tests\test_postgresql_api.py
6 passed, 1 warning

cd frontend; npm run build
passed

.\.venv\Scripts\python.exe -m core.cli --input datasets\samples\small.json --window 120 --method cp_sat --output phase4-core-result.json
PHASE4_CORE_CLI_OK 7 5 ['legacy-parser']

.\.venv\Scripts\python.exe -m core.ingestion.cli --osv datasets\samples\osv_offline.json --inventory datasets\samples\inventory_offline.json --estimates datasets\samples\approved_estimates.json --window 30 --output phase4-ingestion-result.json
PHASE4_INGESTION_CLI_OK 90
```

The PostgreSQL tests explicitly require `DATABASE_URL`, verify the connected
database is `secpatch_test`, and do not fall back to SQLite. The browser smoke
check also verified project creation and environment selection against a fresh
backend; the temporary QA project was removed afterward. The final dashboard
exposes project/environment creation, asset registration, validated inventory
and OSV uploads, explicit estimate inputs, and CP-SAT versus
precedence-greedy selection.

## Final release freeze verification

The final browser verification used a temporary PostgreSQL workspace and the
provided `datasets\samples\inventory_offline.json` and
`datasets\samples\osv_offline.json` fixtures.

- Asset registration succeeded through the frontend for all fixture asset
  identifiers.
- Inventory upload succeeded and displayed 4 persisted package records,
  including multiple versions/unknown version data.
- OSV upload succeeded with 3 deduplicated OSV records, 4 remediation
  candidates, and 2 ingestion issues displayed.
- Explicit duration and benefit inputs were used in a persisted analysis.
- CP-SAT returned `OPTIMAL`, displayed proven optimality, and selected the
  approved action with objective value 90.
- Precedence-greedy returned `FEASIBLE`, displayed not proven, and produced a
  valid result for the same dataset.
- A deterministic optimizer-only comparison confirmed the meaningful gap when
  the uploaded dataset produced the same objective: with a 10-minute window,
  greedy selected `a` for benefit 10, while CP-SAT selected `b` and `c` for
  benefit 16 and returned `OPTIMAL`.
- Desktop (1440px) and mobile (390px) widths had no horizontal overflow.
- After browser refresh, reselecting the persisted project/environment loaded
  both historical analysis records successfully.
- Temporary freeze-check project, environment, assets, inventory, analyses,
  candidates, and related rows were removed in dependency order; the project
  count was verified as zero afterward.

The complete suite covers:

- empty graph
- single and isolated nodes
- disconnected components
- linear and branching graphs
- multiple prerequisites
- self-loops
- multiple SCCs
- transitive impact
- deterministic output
- missing dependency references
- cyclic dependencies and blocked dependent packages/actions
- all prior ingestion, optimizer, scheduler, and validator behavior

The only warning is the existing Starlette/httpx deprecation warning from the FastAPI test client stack.

## Complexity

- Tarjan SCC: `O(V + E)` time and `O(V)` auxiliary space.
- Condensation construction: `O(V + E)`.
- Kahn topological ordering: `O(V + E)` after adjacency construction.
- BFS/DFS traversal: `O(V + E)` worst case.
- Deterministic adjacency/ready-set sorting: up to `O(E log V)` overhead.

## Known limitations

1. Graph nodes currently contain package IDs only; richer package metadata can be added when an approved package catalog contract exists.
2. Critical-path analysis is not implemented because package dependency edges have no valid duration semantics.
3. Package dependency metadata does not automatically create patch-action prerequisites.
4. `atomic_components` remains parsed but is not implemented as an execution policy.
5. Graph validation rejects unknown dependency endpoints but does not yet expose a separate structured graph-ingestion issue type.
6. NVD live ingestion and deployment remain outside the current offline/local scope.

## Next recommended phase

Add a formal package/dependency input schema and benchmark graph datasets, then
consider an optional NVD adapter against the existing Phase 3 normalization
contract. Keep package graph analysis and patch-action scheduling separate.

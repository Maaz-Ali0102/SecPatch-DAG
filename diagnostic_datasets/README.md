# SecPatch-DAG diagnostic datasets

All vulnerability IDs and vulnerability descriptions in this pack are synthetic test records. Package names and version strings are realistic examples, but these are NOT assertions that the named versions are actually vulnerable in production.

## Contents
- `datasets/<scenario>/inventory_offline.json`
- `datasets/<scenario>/osv_offline.json`
- `datasets/<scenario>/approved_estimates.json`
- `datasets/<scenario>/asset_registration_manifest.json` (register these external identifiers before inventory upload)
- `datasets/<scenario>/dataset_manifest.json`
- `datasets/invalid_inputs/` individual negative-test JSON payloads
- `dependency_graph_test_plan.json` graph test specification only, not an upload payload

## Critical setup
1. Register assets in the application using external identifiers that exactly match the `asset_id` values in the inventory JSON.
2. Create a fresh isolated project/environment per dataset, or otherwise ensure run isolation.
3. Upload inventory and OSV payloads using the application's actual UI workflow.
4. Use estimates from the matching scenario only.
5. Keep invalid-input cases separate and run one at a time.
6. Preserve logs and run IDs for each execution.

## Important contract limitation
The inspected input contract describes inventory, OSV and estimates, but does not identify the application's actual package-dependency import/creation payload. Package dependencies are not encoded in the supplied inventory format. The graph plan is therefore a specification, not an invented upload file. Confirm the dependency-management endpoint/UI contract before injecting graph edges.

## Scenario notes
- `baseline`: small mixed affected/unaffected/unknown control set.
- `large_inventory`: 60 assets and a larger mixed PyPI/npm package inventory.
- `non_optimized`: dense competing remediation choices with varied durations/benefits.
- `outliers`: extreme but schema-valid integer values; solver outcomes must be interpreted with solver status.
- `adversarial_graph`: inventory to support graph testing; use the separate graph plan once edge ingestion is known.
- `dirty_but_schema_valid`: missing/invalid versions and unmatched package controls.
- `invalid_inputs`: isolated negative tests for validation behaviour.

## Expected-result caution
For each scenario, validate ingestion and candidate creation against the manifest. Do not treat solver `FEASIBLE` as a defect by itself. For small direct-plan fixtures, independently compute the optimum and verify solver claims. The current pack does not claim exact optimal action selections for the persisted workflow because package dependency ingestion and mandatory-action semantics require the application's full runtime contract.

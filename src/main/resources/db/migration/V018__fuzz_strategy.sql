-- MVP-4: optional fuzz strategy payload on experiment plans.

ALTER TABLE experiment_plans ADD COLUMN fuzz_strategy_json TEXT;

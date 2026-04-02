function assertCondition(condition, message, failures) {
  if (!condition) failures.push(message);
}

function validateContractShape(contract, failures) {
  const hasScenarioCoverage = contract && typeof contract.requiredScenarioCoverage === "object";
  const hasDecisionOutcomes = Array.isArray(contract?.requiredScenarioCoverage?.decisionOutcomes);
  const hasExecutionStatuses = Array.isArray(contract?.requiredScenarioCoverage?.executionStatuses);
  const hasCompleteFlag = typeof contract?.requiredScenarioCoverage?.complete === "boolean";
  const hasControlChecks = contract && typeof contract.requiredControlChecks === "object";
  const hasKeyDistributionControl = typeof contract?.requiredControlChecks?.keyDistribution === "boolean";
  const hasReplayProtectionControl = typeof contract?.requiredControlChecks?.replayProtection === "boolean";
  const hasRequiredRuntimes = Array.isArray(contract?.requiredRuntimes);

  assertCondition(typeof contract?.requiredOverall === "string", "contract.requiredOverall must be a string", failures);
  assertCondition(hasScenarioCoverage, "contract.requiredScenarioCoverage must be an object", failures);
  assertCondition(hasDecisionOutcomes, "contract.requiredScenarioCoverage.decisionOutcomes must be an array", failures);
  assertCondition(hasExecutionStatuses, "contract.requiredScenarioCoverage.executionStatuses must be an array", failures);
  assertCondition(hasCompleteFlag, "contract.requiredScenarioCoverage.complete must be a boolean", failures);
  assertCondition(hasControlChecks, "contract.requiredControlChecks must be an object", failures);
  assertCondition(hasKeyDistributionControl, "contract.requiredControlChecks.keyDistribution must be a boolean", failures);
  assertCondition(hasReplayProtectionControl, "contract.requiredControlChecks.replayProtection must be a boolean", failures);
  assertCondition(hasRequiredRuntimes, "contract.requiredRuntimes must be an array", failures);

  if (hasDecisionOutcomes) {
    assertCondition(contract.requiredScenarioCoverage.decisionOutcomes.length > 0, "contract decisionOutcomes must not be empty", failures);
  }
  if (hasExecutionStatuses) {
    assertCondition(contract.requiredScenarioCoverage.executionStatuses.length > 0, "contract executionStatuses must not be empty", failures);
  }
  if (hasRequiredRuntimes) {
    assertCondition(contract.requiredRuntimes.length > 0, "contract requiredRuntimes must not be empty", failures);
    contract.requiredRuntimes.forEach((requirement, idx) => {
      const path = `contract.requiredRuntimes[${idx}]`;
      assertCondition(requirement && typeof requirement === "object", `${path} must be an object`, failures);
      if (!requirement || typeof requirement !== "object") return;
      assertCondition(typeof requirement.runtimeId === "string" && requirement.runtimeId.trim().length > 0, `${path}.runtimeId must be a non-empty string`, failures);
      if (Object.hasOwn(requirement, "passed")) {
        assertCondition(typeof requirement.passed === "boolean", `${path}.passed must be boolean`, failures);
      }
      if (Object.hasOwn(requirement, "requiredLevel")) {
        assertCondition(typeof requirement.requiredLevel === "string", `${path}.requiredLevel must be string`, failures);
      }
      if (Object.hasOwn(requirement, "requiredAtpL1")) {
        assertCondition(typeof requirement.requiredAtpL1 === "boolean", `${path}.requiredAtpL1 must be boolean`, failures);
      }
      if (Object.hasOwn(requirement, "atpValid")) {
        assertCondition(typeof requirement.atpValid === "boolean", `${path}.atpValid must be boolean`, failures);
      }
    });
  }
}

export function validateConformanceReport(report, contract) {
  const failures = [];
  validateContractShape(contract, failures);
  if (failures.length > 0) return { ok: false, failures };

  assertCondition(
    String(report?.overall ?? "") === String(contract.requiredOverall),
    `overall expected '${contract.requiredOverall}' but got '${report?.overall}'`,
    failures
  );

  const requiredDecisionOutcomes = contract.requiredScenarioCoverage.decisionOutcomes;
  const requiredExecutionStatuses = contract.requiredScenarioCoverage.executionStatuses;
  const coveredDecisionOutcomes = new Set(report?.scenarioCoverage?.decisionOutcomes?.covered ?? []);
  const coveredExecutionStatuses = new Set(report?.scenarioCoverage?.executionStatuses?.covered ?? []);
  for (const outcome of requiredDecisionOutcomes) {
    assertCondition(coveredDecisionOutcomes.has(outcome), `scenario coverage missing decision outcome '${outcome}'`, failures);
  }
  for (const status of requiredExecutionStatuses) {
    assertCondition(coveredExecutionStatuses.has(status), `scenario coverage missing execution status '${status}'`, failures);
  }
  if (contract.requiredScenarioCoverage.complete === true) {
    assertCondition(report?.scenarioCoverage?.complete === true, "scenario coverage expected complete=true", failures);
  }
  if (typeof contract?.requiredControlChecks?.keyDistribution === "boolean") {
    assertCondition(
      Boolean(report?.controlChecks?.keyDistribution) === contract.requiredControlChecks.keyDistribution,
      `control check keyDistribution expected ${contract.requiredControlChecks.keyDistribution}`,
      failures
    );
  }
  if (typeof contract?.requiredControlChecks?.replayProtection === "boolean") {
    assertCondition(
      Boolean(report?.controlChecks?.replayProtection) === contract.requiredControlChecks.replayProtection,
      `control check replayProtection expected ${contract.requiredControlChecks.replayProtection}`,
      failures
    );
  }

  const requiredRuntimes = contract.requiredRuntimes;
  const resultByRuntimeId = new Map(
    (Array.isArray(report?.results) ? report.results : []).map((entry) => [String(entry.runtimeId), entry])
  );
  for (const requirement of requiredRuntimes) {
    const runtimeId = String(requirement?.runtimeId ?? "");
    const entry = resultByRuntimeId.get(runtimeId);
    assertCondition(Boolean(entry), `missing runtime result '${runtimeId}'`, failures);
    if (!entry) continue;
    if (typeof requirement?.passed === "boolean") {
      assertCondition(entry.passed === requirement.passed, `runtime '${runtimeId}' passed expected ${requirement.passed}`, failures);
    }
    if (typeof requirement?.requiredLevel === "string") {
      assertCondition(
        String(entry.requiredLevel) === requirement.requiredLevel,
        `runtime '${runtimeId}' requiredLevel expected '${requirement.requiredLevel}'`,
        failures
      );
    }
    if (typeof requirement?.requiredAtpL1 === "boolean") {
      assertCondition(
        Boolean(entry.requiredAtpL1) === requirement.requiredAtpL1,
        `runtime '${runtimeId}' requiredAtpL1 expected ${requirement.requiredAtpL1}`,
        failures
      );
    }
    if (typeof requirement?.atpValid === "boolean") {
      assertCondition(
        Boolean(entry?.atpL1?.valid) === requirement.atpValid,
        `runtime '${runtimeId}' atpL1.valid expected ${requirement.atpValid}`,
        failures
      );
    }
  }

  return { ok: failures.length === 0, failures };
}

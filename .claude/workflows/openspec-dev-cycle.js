// ── openspec-dev-cycle ──
// Full pipeline using proper skills at each phase.
//
// Usage:
//   /openspec-dev-cycle my-change-name
//   /openspec-dev-cycle change-a change-b
//
// Skills used:
//   openspec-apply-change  → implement
//   openspec-verify-change → verify
//   simplify               → simplification (effort: high)
//   code-review            → bug/security review (effort: max)
//   openspec-sync-specs    → sync delta specs to main
//   openspec-archive-change → archive

export const meta = {
  name: 'openspec-dev-cycle',
  description: 'Full dev cycle: implement, build, e2e, verify, simplify, code-review (max), fix, sync, archive. Accepts 1+ change names.',
  phases: [
    { title: 'Implement', detail: 'openspec-apply-change skill → implements code tasks' },
    { title: 'Build+E2E', detail: 'Build, lint, then E2E tests from spec scenarios' },
    { title: 'Verify', detail: 'openspec-verify-change skill' },
    { title: 'Simplify', detail: 'simplify skill (effort: max)' },
    { title: 'Code Review', detail: 'code-review skill (effort: max)' },
    { title: 'Fix', detail: 'Apply all review + simplify findings' },
    { title: 'Sync+Archive', detail: 'openspec-sync-specs then openspec-archive-change' },
  ],
}

let changeNames
if (Array.isArray(args)) {
  changeNames = args
} else if (typeof args === 'string') {
  changeNames = args.split(/\s+/).filter(Boolean)
} else {
  log('ERROR: change name(s) required. Usage: /openspec-dev-cycle change-a [change-b ...]')
  throw new Error('changeNames required')
}

if (!changeNames.length) {
  log('ERROR: at least one change name required')
  throw new Error('changeNames required')
}

log(`OpenSpec dev cycle: ${changeNames.join(', ')} (${changeNames.length} change(s))`)

const results = []

for (let i = 0; i < changeNames.length; i++) {
  const changeName = changeNames[i]
  const changeDir = `openspec/changes/${changeName}`
  const label = `[${i + 1}/${changeNames.length}]`

  log(`${label} Starting: ${changeName}`)

  let simplifyResult, reviewResult

  phase('Implement')
  await agent(
    `Invoke the openspec-apply-change skill for change "${changeName}".
Implement ALL code tasks from the change. Mark each task [x] in ${changeDir}/tasks.md.
After all edits, run build + lint (from CLAUDE.md) and fix any failures.
Return a summary of what was implemented and how many tasks.`,
    { model: 'sonnet', effort: 'high' }
  )
  log(`${label} Implement done: ${changeName}`)

  phase('Build+E2E')
  const buildE2eResult = await agent(
    `Two steps for change "${changeName}":

STEP 1 — Build & Lint:
Run the project build and lint commands (from CLAUDE.md). Report pass/fail.

STEP 2 — E2E Tests:
Read ${changeDir}/specs/**/*.md — extract every "Scenario:" block (WHEN/THEN/AND).
Then design and run E2E tests for each scenario:
- Build the project
- Run the binary with real config files on disk (never mocks)
- Verify every THEN/AND condition
- Test edge cases: corrupted inputs, clean inputs, trigger inputs
- Regression: things that shouldn't change still work

Report: "BUILD: pass|fail", "LINT: pass|fail", "E2E: N/M passed" with per-test results.`,
    { model: 'sonnet', effort: 'high' }
  )
  log(`${label} Build+E2E: ${buildE2eResult?.substring(0, 300)}`)

  phase('Verify')
  const verifyResult = await agent(
    `Run TWO verification passes for change "${changeName}":

PASS 1 — Invoke the verify skill.
This runs the actual binary/server, tests with real files on disk, and verifies
that the change actually works — not just that tasks are checked off.

PASS 2 — Invoke the openspec-verify-change skill.
This checks artifacts: completeness (tasks done, requirements covered),
correctness (each requirement traced to implementation), coherence (design followed).

Combine both reports. Report: "VERIFY: PASS" or "VERIFY: FAIL: <list>"`,
    { model: 'sonnet', effort: 'high' }
  )
  log(`${label} Verify: ${verifyResult?.substring(0, 400)}`)

  phase('Simplify')
  simplifyResult = await agent(
    `Invoke the simplify skill on the diff for change "${changeName}".
Use effort: max.
The skill reviews changed code for reuse, simplification, efficiency, and altitude cleanups.
It does NOT hunt for bugs — that's the code-review phase next.
Return every finding and what was fixed.`,
    { model: 'sonnet', effort: 'max' }
  )
  log(`${label} Simplify: ${simplifyResult?.substring(0, 300)}`)

  phase('Code Review')
  reviewResult = await agent(
    `Invoke the code-review skill on the diff for change "${changeName}".
Use effort: max.
The skill reviews for correctness bugs and security issues.
Unlike simplify, this IS hunting for bugs.
Return every finding with severity and fix.`,
    { model: 'sonnet', effort: 'max' }
  )
  log(`${label} Review: ${reviewResult?.substring(0, 300)}`)

  phase('Fix')
  const fixResult = await agent(
    `Apply ALL findings from the simplify and code-review phases for "${changeName}".

Simplify findings:
${simplifyResult?.substring(0, 1000)}

Code review findings:
${reviewResult?.substring(0, 1000)}

1. Apply every finding that is genuine (skip wrong ones, explain why)
2. Run build + lint (from CLAUDE.md). Fix until both pass.
3. If the simplify skill already applied its own findings, don't double-apply

Follow ALL project standards from CLAUDE.md.
Report: "FIXES: <applied>/<total>. BUILD: pass|fail. LINT: pass|fail"`,
    { model: 'sonnet', effort: 'high' }
  )
  log(`${label} Fixes: ${fixResult}`)

  phase('Sync+Archive')
  const syncResult = await agent(
    `Invoke the openspec-sync-specs skill for change "${changeName}".
This syncs delta specs from the change into the main specs directory.
Report the result. If it fails because main specs are already up to date, that's fine — note it.`,
    { model: 'haiku' }
  )
  log(`${label} Sync: ${syncResult}`)

  const archiveResult = await agent(
    `Invoke the openspec-archive-change skill for change "${changeName}".
This archives the completed change.
Report the result.`,
    { model: 'haiku' }
  )
  log(`${label} Archive: ${archiveResult}`)

  results.push({
    change: changeName,
    buildE2e: buildE2eResult?.substring(0, 400),
    verify: verifyResult?.substring(0, 300),
    simplify: simplifyResult?.substring(0, 300),
    review: reviewResult?.substring(0, 300),
    fixes: fixResult,
    sync: syncResult,
    archive: archiveResult,
  })
}

return {
  total: changeNames.length,
  changes: results,
}

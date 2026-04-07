# Harrier Ops Kube Agent Guidance

This file captures project-specific guidance that should stay true even as the codebase grows.

## Startup

Before substantial implementation, review, or publish work:

- re-read this file
- check the current handover and planning notes in `~/Documents/HarrierOps-Kube-reference/`
- prefer the latest recorded product decisions over stale thread memory

## Branch And PR Naming

- Do not use `codex` in branch names or pull request titles unless the user explicitly asks for it.

## Code Readability

Prefer code that explains itself, but do not avoid comments so aggressively that non-obvious
product logic becomes hard to follow.

- Use names that reflect product meaning, not just implementation shape.
- Prefer specific names over placeholders like `data`, `info`, `result`, `item`, `helper`, or
  `manager` when a sharper name exists.
- Keep functions and conditionals small enough that intent is visible without narration.
- Restructure code before adding comments that only explain mechanics.
- Add comments when they preserve intent the code cannot make obvious on its own.
- Do not add abstraction layers before the product meaning is stable.
- Do not force symmetry across commands just because their shapes look similar; if the product
  behavior is different, let the code reflect that.
- Do not hide uncertainty or failure behind vague empty fallbacks just to keep code looking neat.

Readable code is not just "few comments." It also means:

- names that carry real meaning
- boundaries that stay clear
- control flow a reviewer can trust on first read
- product logic that is visible instead of buried in helpers

Watch for these failure modes in generated or fast-moving code:

- fake certainty: stronger claims than the evidence supports
- silent degradation: empty or partial fallbacks that hide uncertainty
- premature abstraction: reusable layers built before the product meaning is stable
- symmetry bias: forcing commands into the same shape when their operator meaning differs
- output drift: code still works, but ranking, evidence boundaries, or contract meaning quietly drift

## Comments

Good comments should sound like a useful note from one engineer to another.

Use comments for things like:

- evidence-boundary rules
- proof-state or ranking decisions that would be easy to "simplify" incorrectly later
- non-obvious Kubernetes or API behavior
- security constraints or assumptions
- temporary workarounds that should be revisited

Avoid comments that:

- narrate obvious loops, assignments, or conditionals
- restate the function name or type signature
- compensate for vague names or over-complicated code
- read like policy prose instead of teammate guidance

Good comment style:

```go
// Real lead, fuzzy target: keep it visible.
```

```go
// Kubernetes returns forbidden here when scope is real but unreadable.
```

Avoid comments like:

```go
// Loop through the workloads and add exposed ones to the result.
```

## Output And Product Logic

When code implements product meaning, prefer one short comment that explains the decision boundary
instead of several comments that explain the mechanics.

Do not optimize only for "the tool works."

Also optimize for:

- code a human can review without reverse-engineering intent
- output logic that preserves evidence truthfully
- structure that can evolve without quietly drifting product boundaries

The goal is not "few comments at all costs." The goal is:

- readable code
- clear product intent
- comments only where they preserve truth, boundaries, or non-obvious behavior

---
name: Bug
about: A defect that is not being fixed in the change at hand
title: ''
labels: bug
assignees: ''
---

## What's wrong

One or two sentences. The defect, not the story around it.

## Where

`path/to/file.ext:123` — the narrowest location you can name. If it spans
components, name them.

## Expected vs. observed

- **Expected:** …
- **Observed:** …

Paste the shortest output that shows it.

## Repro

Minimal steps: a command, a single test, or a query that returns the wrong
result. If it isn't reproducible on demand, say so and give the conditions
under which it was seen.

## Blast radius

What is wrong downstream because of this — what is affected, how much, and
whether stored data is corrupted vs. merely missing. **State whether any number
is measured or estimated.**

## Workaround

What to do until it's fixed, or "none".

## Found during

The work that surfaced it (`#<issue>`, PR, or date). Context for whoever picks
it up — this issue stands on its own, outside the initiative that found it.

---
description: Perform a refactor pass focused on simplicity after recent changes
---
Perform a refactor pass on the recent changes with this workflow:

1. Review the changes and identify simplification opportunities.
2. Apply refactors to:
   - Remove dead code and dead paths.
   - Straighten logic flows.
   - Remove excessive parameters.
   - Remove premature optimization.
3. Run build/tests to verify behavior.
4. Identify optional abstractions or reusable patterns; suggest them only if they clearly improve clarity, and keep suggestions brief.

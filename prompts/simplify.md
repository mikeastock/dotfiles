---
description: Brainstorm a code simplification plan before implementation
---
I want to design a code simplification pass for: $@

This is a design/brainstorm step only (no edits yet).
If I invoke `/skill:brainstorm` after this, continue seamlessly with one-question-at-a-time discovery using this same context.

Use these requirements:

1. **Preserve Functionality**: Never change what the code does - only how it does it. All original features, outputs, and behaviors must remain intact.

2. **Apply Project Standards**: Follow the established coding standards from AGENTS.md.

3. **Enhance Clarity**: Simplify code structure by:
   - Reducing unnecessary complexity and nesting
   - Eliminating redundant code and abstractions
   - Improving readability through clear variable and function names
   - Consolidating related logic
   - Removing unnecessary comments that describe obvious code
   - Avoid nested ternary operators - prefer switch statements or if/else chains for multiple conditions
   - Choose clarity over brevity - explicit code is often better than overly compact code

4. **Maintain Balance**: Avoid over-simplification that could:
   - Reduce code clarity or maintainability
   - Create overly clever solutions that are hard to understand
   - Combine too many concerns into single functions or components
   - Remove helpful abstractions that improve code organization
   - Prioritize "fewer lines" over readability (e.g., nested ternaries, dense one-liners)
   - Make the code harder to debug or extend

5. **Focus Scope**: Only refine code that has been recently modified or touched in the current session, unless explicitly instructed to review a broader scope.

Include this concrete refinement process in the plan:
1. Identify the recently modified code sections
2. Analyze for opportunities to improve elegance and consistency
3. Apply project-specific best practices and coding standards
4. Ensure all functionality remains unchanged
5. Verify the refined code is simpler and more maintainable
6. Document only significant changes that affect understanding

Brainstorm output should include:
1. Scope strategy
2. Simplification rubric
3. Safety guardrails
4. Review workflow
5. Verification plan
6. Minimal execution checklist

Process constraints:
- Ask one clarifying question at a time.
- Prefer multiple-choice questions when possible.
- End with a practical minimal plan ready for implementation.

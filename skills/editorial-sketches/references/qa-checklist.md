# QA Checklist

## Must Pass

- The image is 16:9 horizontal.
- The background is clean white.
- Xiaohei is present.
- Xiaohei performs the core action and is not just decoration.
- The image does not copy an old example composition; it creates a new metaphor for the current article.
- The image is strange, creative, and interesting.
- The image is clean and spacious; the main subject takes up no more than about 60% of the canvas.
- One image explains only one core structure.
- Handwritten annotations are sparse, short, readable, and in the source language unless the user requested another language.
- Orange is used only for the main path or arrows.
- Red is used only for emphasis, problems, reminders, or results.
- Blue is used only for secondary notes, feedback, or system state.

## Failure Signals

If any of these appear, regenerate or edit locally:

- The top-left corner contains a title such as "Pitfalls", "Workflow", "System Architecture", or "Roadmap".
- Xiaohei looks like a mascot, meme character, or cute cartoon.
- The image looks like a PPT slide, course slide, or formal flowchart.
- There are too many elements, arrows, or nodes.
- Text turns into long explanations.
- The background has paper texture, shadow, gradient, beige color, or noise.
- The image contains real UI screenshots or a techy interface.
- Text has severe errors or labels are unreadable.
- The image is too stiff and lacks an absurd metaphor.
- The composition is too similar to an old example in `assets/examples/`.

## Iteration Methods

- Too ordinary: make Xiaohei the action subject and add a strange but valid metaphor.
- Too complex: remove nodes and keep only one action plus 3-5 short labels.
- Too cute: emphasize deadpan, blank serious expression, not cute, not mascot.
- Too PPT-like: remove titles, borders, regular grids, and excessive arrows; turn it into a hand-drawn scene.
- Too close to an old example: keep the core meaning but change the main object and Xiaohei's action.
- Text is wrong: prefer local editing; if many labels are wrong, regenerate with fewer labels.

## Delivery Standard

A high-quality image should make the reader first think "that is a little strange", then understand the structure within one second.

If the first impression is a tutorial page rather than a strange product sketch on white paper, it fails.

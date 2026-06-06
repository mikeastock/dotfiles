---
name: editorial-sketches
description: Generate Ian-style inline editorial illustrations for articles in any language. Use when the user asks for strange, hand-drawn, Xiaohei-style article illustrations, image concepts, shot lists, title removal, or image edits for articles, essays, posts, blogs, Notion docs, workflow docs, methods, processes, structures, states, metaphors, or arguments. Defaults to the Xiaohei character, pure white hand-drawn visuals, sparse red/orange/blue annotations in the source language, and a clean, restrained, imaginative visual style.
---

# Strange Xiaohei Article Illustrations

## Core Purpose

Design and generate 16:9 horizontal inline illustrations for articles, essays, posts, and editorial documents in any language. The goal is not commercial illustration, PPT infographics, or cute cartoons. The goal is to turn a key judgment, process, structure, state, or metaphor from the source text into a clean, strange, creative, readable hand-drawn explanatory image that does not feel like an instruction manual.

The default visual character is Xiaohei: a solid black figure with white dot eyes, thin legs, and a blank expression, seriously doing something absurd but conceptually valid. Xiaohei must participate in the image's core action, not stand off to the side as decoration.

## Read These References First

Read only what the task needs; do not load everything into context by default:

- `references/style-dna.md`: style DNA, colors, text rules, and prohibitions.
- `references/xiaohei-ip.md`: Xiaohei's appearance, personality, action library, and prohibitions.
- `references/composition-patterns.md`: structure types, original-metaphor method, and anti-copying rules.
- `references/prompt-template.md`: single-image generation prompt template.
- `references/qa-checklist.md`: post-generation checks and iteration rules.
- `assets/examples/`: low-frequency visual calibration only. Do not copy these examples' compositions, objects, or labels.

## Workflow

### 1. Digest The Article

First read the user's article, link, Notion page, Markdown file, or screenshot content. Extract:

- the core argument
- which sections create cognitive turns
- which points are worth explaining visually
- which points should stay as text and do not need images

Do not distribute illustrations evenly through the article. Prefer cognitive anchors such as a core judgment, two breakpoints, an input-output loop, branching, before/after contrast, one-source-many-uses, a handoff path, common pitfalls, or a role-state change.

### 2. Produce An Illustration Strategy First

If the user asks to analyze how to illustrate the article or where illustrations are needed, produce a shot list first. For each image, state:

- where it should appear in the article
- the image theme
- the core idea
- the structure type
- what Xiaohei does in the image
- suggested visual elements
- suggested short label text in the source language

Default to 4-8 images. Use 1-3 for a short article. Avoid exceeding 9 even for long articles unless the user explicitly asks. Use only as many as the article needs; do not turn the article into a picture book.

### 3. Generate Single Images

If the user explicitly asks to generate, output, create, or make images, do not stop for confirmation. Use the built-in `image_gen` tool and generate each image separately. Do not combine multiple illustrations into one image.

Each image should explain one core structure. The prompt must include:

- 16:9 horizontal inline editorial illustration
- pure white background
- black hand-drawn line art
- sparse red/orange/blue handwritten annotations in the source language
- lots of empty space
- Xiaohei as the subject performing the core action
- no PPT, commercial illustration, childish cuteness, complex architecture diagram, or top-left structure title

Do not copy prior examples. Examples only calibrate style density and Xiaohei's level of participation. Do not directly reuse existing compositions such as conveyor breakpoints, Xiaohei pulling wires, a material fish, a stamp toolbox, or a common-pitfall path unless the user explicitly asks to recreate a specific image. Invent a strange but valid metaphor from the current article every time.

### 4. Check And Iterate

After generation, check `references/qa-checklist.md`. If any of these issues appear, regenerate or edit locally first:

- Xiaohei is only decorative
- the image is too crowded
- the image looks too much like a flowchart or PPT slide
- there is too much text or severe text corruption
- the top-left corner contains a title such as "pitfalls", "flowchart", or "system architecture"
- the style is too cute, childish, or stiff
- the background is not clean white

### 5. Save And Deliver

If the user is working inside a workspace, copy the final images to:

```text
assets/<article-slug>-illustrations/
```

Name them in order:

```text
01-topic-name.png
02-topic-name.png
```

Keep the original generated files. Do not overwrite existing assets unless the user explicitly asks for replacement.

## Response Style

Before generation, keep the strategy short and precise. After generation, include:

- how many images were generated
- what each image is for
- the save path
- which images are strongest and which are optional

Do not explain the style theory at length. Let the images carry the explanation.

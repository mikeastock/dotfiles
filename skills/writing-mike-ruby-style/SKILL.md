---
name: writing-mike-ruby-style
description: Write and review Ruby/Rails code in Mike's personal style — parens, conditional shape, raising finders, operations and PORO shape. Use whenever writing, refactoring, or reviewing Ruby, or when the user asks for Mike's Ruby style.
metadata:
  agents: amp, claude, codex, pi
---

# Writing Mike Ruby Style

Write Ruby that can be read once: plain, domain-named, linear, explicit, and allergic to generic-agent cleverness.

| Agent default | Mike's style |
| --- | --- |
| Reflexive guard return | Judgment — usually invert into a block `if`; keep the return when it reads better |
| Stacked guard exits | One `if`/`elsif`/`else` |
| Bare `render :new, status: ...` | `render(:new, status: ...)` |
| `find_by` plus a nil check | `find`, then delete the dead guard |
| Single-use explaining variable | Inline the trivial expression |
| Inline guard at the top of a controller action | `before_action` |
| `before_action :set_project` + `@project` ivars | Look the record up in the action, pass `locals:` |
| Long `&.` chain | Fail fast at the source |
| `OpenStruct` / `yield_self` | PORO / `then` |

## Parentheses

Use parentheses for ordinary calls with arguments, including Rails response calls and assertions:

```ruby
Operations::UpdateProject.new(
  project: project,
  attributes: project_params,
  user: current_user,
).call

render(:show, locals: {project: project})
redirect_to(project_path(project), notice: "Project updated")
```

Leave DSL-shaped declarations bare:

```ruby
belongs_to :account
has_many :projects
validates :name, presence: true
before_action :set_project
```

Format vertical chains with leading dots after the first call:

```ruby
Operations::UpdateProject.new(project:, attributes:, user:)
  .with_context(controller: self)
  .call
```

## Conditionals

Early returns are a judgment call, not a ban. Default to the shape that reads most explicitly — usually a block `if`/`else`, because it puts both paths on the page (never a trailing modifier for real logic). Keep an early return when it genuinely reads better: a trivial boundary bail, framework-shaped code, a method where inversion would nest the real work. When in doubt, choose the more explicit shape; what stays out is reflexive guard-stacking as a habit.

Instead of:

```ruby
return unless user.project_admin?(project)

project.update!(project_params)
```

Write:

```ruby
if user.project_admin?(project)
  project.update!(project_params)
end
```

Use `if`/`else` over guard exits, including memoization. Memoize a single expression; bump a branching computation into its own method:

```ruby
def sync_status
  @sync_status ||= computed_sync_status
end

def computed_sync_status
  if user.last_synced_at&.after?(1.hour.ago)
    :recently_synced
  else
    :stale
  end
end
```

Collapse stacked guards into one condition block.

Instead of:

```ruby
def show
  schedule = current_project.schedule
  return render(json: {error: "Project schedule is required"}, status: :unprocessable_content) if schedule.blank?

  milestone = schedule.current_milestone
  return render(json: {error: "Schedule has no current milestone"}, status: :unprocessable_content) if milestone.blank?

  render(json: MilestoneSerializer.new(milestone))
end
```

Write:

```ruby
def show
  schedule = current_project.schedule

  if schedule.blank?
    render(json: {error: "Project schedule is required"}, status: :unprocessable_content)
  elsif schedule.current_milestone.blank?
    render(json: {error: "Schedule has no current milestone"}, status: :unprocessable_content)
  else
    render(json: MilestoneSerializer.new(schedule.current_milestone))
  end
end
```

Trailing conditionals survive only as loop-control guards, and even those are rare:

```ruby
rows.each do |row|
  next if row.blank?
  import_row(row)
end
```

Put raises inside block conditionals.

Instead of:

```ruby
raise(ProjectArchivedError, "Cannot update archived project") if project.archived?
```

Write:

```ruby
if project.archived?
  raise(ProjectArchivedError, "Cannot update archived project")
end
```

Avoid ternaries for domain logic. Avoid inline rescue fallbacks; put recovery at method level.

## Blocks And Expressions

Use `do`/`end` for procedural blocks:

```ruby
assert_difference(-> { Project.count }, +1) do
  click_button("Create project")
end
```

Use braces for expression-shaped blocks, even multiline scopes:

```ruby
scope :ordered, -> { order(:position) }

scope :with_bid_due_at_between, ->(range) {
  date_optional_time_scope(:bid_due_at).between(range.begin, range.end)
}
```

Use `then` for transformation pipelines:

```ruby
raw_attributes
  .then { |attributes| cast_probability(attributes) }
  .then { |attributes| cast_amount(attributes) }
```

Use `tap` only when returning the configured object is the point.

## Locals

Do not create single-use locals for trivial expressions.

Instead of:

```ruby
project_id = params.fetch(:project_id)
project = current_account.projects.find(project_id)
```

Write:

```ruby
project = current_account.projects.find(params.fetch(:project_id))
```

Name a value when it is used more than once, or when the inline form is genuinely unreadable — a nontrivial chain earns its name even with one use:

```ruby
active_memberships = project.team_memberships.kept
notify_admins(active_memberships.project_admins)
notify_collaborators(active_memberships.collaborators)
```

```ruby
admin_user_ids = project.team_memberships.kept.project_admins.pluck(:user_id)
notify_admins(admin_user_ids)
```

## Hashes, Keywords, And Commas

Use shorthand keywords when they read naturally, and use trailing commas in multiline calls:

```ruby
ProjectSummary.new(project:, totals:)
project.update!(
  name:,
  starts_on:,
)
```

## Nil, Presence, And Finders

Use Rails presence tools naturally: `present?`, `blank?`, `presence`, `compact`, and `compact_blank`.

Safe navigation is fine for a short nullable check:

```ruby
if user.last_synced_at&.after?(1.hour.ago)
  sync_status = :recently_synced
end
```

Do not build long uncertain chains with `&.`. If a value must exist, make that truth loud near the source:

```ruby
class ProjectsController < ApplicationController
  def show
    project = current_account.projects.find(params.fetch(:id))

    authorize!(project, to: :show?)

    render(:show, locals: {project: project})
  end
end
```

Use raising finders when absence is exceptional: `find` over `find_by`, `first!` over `first`. Let the finder raise and delete the nil guards the raise makes dead.

Instead of:

```ruby
project = current_account.projects.find_by(id: params[:id])

if project.nil?
  redirect_to(projects_path, alert: "Project not found")
else
  authorize!(project, to: :show?)
end
```

Write:

```ruby
project = current_account.projects.find(params[:id])
authorize!(project, to: :show?)
```

Fail fast at the source instead of threading `nil` through a workflow.

## Controllers

Request-level guards are `before_action`s, not inline checks at the top of actions:

```ruby
class ProjectsController < ApplicationController
  before_action :require_project_admin, only: [:edit, :update]

  def update
    redirect_to(project_path(update_project), notice: "Project updated")
  end

  private

  def require_project_admin
    if !current_user.project_admin?(current_project)
      redirect_to(project_path(current_project), alert: "Not authorized")
    end
  end
end
```

`before_action` is for request-level guards only — never `set_*` record-loading `before_action`s. Look records up in the action and pass them to views as `locals:`, not ivars.

Keep `render(...)` and `redirect_to(...)` parenthesized as shown in Parentheses.

## Plain Ruby Objects

Use small POROs for deterministic calculation, mapping, formatting, or branching:

```ruby
class ReferenceNumberBuilder
  def initialize(level1:, level2:, level3:, level4:)
    @level1 = level1
    @level2 = level2
    @level3 = level3
    @level4 = level4
  end

  def call
    [level1, level2, level3, level4].compact_blank.join("-")
  end

  private

  attr_reader :level1, :level2, :level3, :level4
end
```

## Hard No

- No `raise ... if ...`.
- No single-use locals.
- No `set_*` record-loading `before_action`s or controller ivars for records.
- No `OpenStruct`.
- No `yield_self`.
- No inline rescue fallbacks.
- No dense ternaries for domain logic.
- No trailing conditionals for meaningful branches.
- No long safe-navigation chains.
- No broad `rescue` around normal ActiveRecord behavior.

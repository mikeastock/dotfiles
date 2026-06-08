---
name: writing-mike-ruby-style
description: Writes and reviews Ruby/Rails code in Michael Stock's personal Ruby style. Use when writing Ruby, refactoring Rails code, reviewing Ruby changes, or when the user asks for Mike's Ruby style, paren preferences, conditional style, or Ruby nitpicks.
---

# Writing Mike Ruby Style

This is a Ruby taste skill: syntax, expression shape, object shape, and idioms.

Make the Ruby feel like Mike wrote it: plain, domain-named, linear, explicit,
and allergic to generic-agent cleverness.

## The Feel

Write Ruby that can be read once.

- Prefer ordinary Ruby over clever Ruby.
- Prefer domain nouns over generic helper names.
- Prefer a visible workflow over a maze of tiny private methods.
- Prefer explicit branches over defensive anxiety.

If code is technically correct but has generic-agent texture, rewrite it.

## Parentheses

My personal style is to use parentheses for ordinary Ruby calls with arguments,
even in places where common Rails style often leaves them off. This is the
default for application code, especially when a call has keyword arguments,
options, or multiple lines:

```ruby
Operations::UpdateProject.new(
  project: project,
  attributes: project_params,
  user: current_user,
).call
```

Use parentheses for controller response calls like `render` and `redirect_to`,
even when the call is short:

```ruby
render(
  :new,
  status: :unprocessable_entity,
  locals: {project: project},
)

render(:show, locals: {project: project})
redirect_to(project_path(project), notice: "Project updated")
```

Use parentheses for assertions. Treat parens on asserts as the default, not a
special case for complex arguments:

```ruby
assert_equal(expected_name, project.reload.name)
assert_nil(project.archived_at)
assert_response(:success)
```

The exception is the small subset of Ruby that is intentionally DSL-shaped:
class-level Rails declarations, callbacks, scopes, routes, and simple
module-mixing lines. Leave those bare:

```ruby
belongs_to :account
has_many :projects
validates :name, presence: true
before_action :set_project
include SoftDelete
scope :active, -> { kept }

resources :projects, only: [:index, :show]
```

When a chain spans multiple conceptual steps, format it vertically with leading
dots after the first call:

```ruby
Operations::UpdateProject.new(
  project: project,
  attributes: project_params,
  user: current_user,
)
  .with_context(controller: self)
  .call
```

## Conditionals

Use ordinary `if`, `elsif`, `else`, and `case` for real logic.

Do not hide meaningful branches in trailing conditionals:

```ruby
if user.project_admin?(project)
  project.update!(project_params)
else
  raise NotAuthorized
end
```

Use trailing conditionals sparingly, and only for simple flow-control guards:

```ruby
return if already_synced?
next if row.blank?
```

Avoid ternaries unless the value is tiny and obvious. If the branch has domain
meaning, write the branch out.

Avoid inline rescue fallbacks. Put the happy path first and the recovery path at
method level:

```ruby
def create
  project = Operations::CreateProject.new(
    account: current_account,
    attributes: project_params,
    user: current_user,
  ).call

  redirect_to(project_path(project), notice: "Project created")
rescue ActiveRecord::RecordInvalid => e
  render(:new, status: :unprocessable_entity, locals: {project: e.record})
end
```

## Blocks And Expressions

Use `do`/`end` for procedural blocks, action blocks, setup blocks, and blocks
whose point is the sequence of statements:

```ruby
assert_difference(-> { Project.count }, +1) do
  click_button("Create project")
end
```

Use `{ ... }` for expression-shaped blocks: scopes, lambdas, short enumerable
transforms, assertions, and value pipelines. This is about the shape of the
block, not only the line count; multiline scopes and transformation blocks can
still use braces:

```ruby
scope :ordered, -> { order(:position) }

scope :with_bid_due_at_between, ->(range) {
  date_optional_time_scope(:bid_due_at).between(range.begin, range.end)
}
```

Prefer named locals over expression gymnastics:

```ruby
active_memberships = project.team_memberships.kept
project_admin_ids = active_memberships.project_admins.pluck(:user_id)
```

Use `then` for clear transformation pipelines when each step returns the next
value:

```ruby
raw_attributes
  .then { |attr| cast_probability(attr) }
  .then { |attr| cast_fee_percent(attr) }
  .then { |attr| cast_amount(attr) }
```

Use `tap` when mutating or configuring an object and returning that same object
is the point. Do not use `tap` just to hide extra work inside an expression.

Do not use `yield_self`.

## Hashes, Keywords, And Commas

Use modern keyword and hash syntax:

```ruby
attributes = {
  account_id: account.id,
  name:,
  starts_on:,
}

ProjectSummary.new(project:, totals:)
```

Use shorthand keywords when they read naturally. Do not contort names just to
use shorthand.

Use trailing commas in multiline calls, arrays, and hashes:

```ruby
project.update!(
  name:,
  starts_on:,
  ends_on:,
)
```

Prefer one named intermediate variable per concept over deeply nested calls.

## Nil And Presence

Use Rails presence tools naturally:

- `present?`
- `blank?`
- `presence`
- `compact`
- `compact_blank`

Safe navigation is fine for a short nullable check:

```ruby
if user.last_synced_at&.after?(1.hour.ago)
  sync_status = :recently_synced
end
```

Do not build long uncertain chains with `&.`. If a value must exist, make that
truth loud with `fetch`, `find_by!`, bang persistence, or an explicit error.
Fail near the source of the bad state instead of passing `nil` through the
workflow and making the real bug show up somewhere unrelated.

## Operations

Our operations pattern is an imperative shell. Use operations to coordinate Rails
side effects: scoped lookup, authorization, transactions, persistence, jobs,
emails, tracking, and webhooks. Keep `call` as the visible workflow. Use private
helpers for after-transaction hooks when that keeps the workflow readable:

```ruby
class Operations::CreateProject
  def initialize(account:, attributes:, user:)
    @account = account
    @attributes = attributes
    @user = user
  end

  def call
    project = Project.transaction do
      project = account.projects.build(project_attributes)

      authorize!(project, to: :create?, context: {user: user})
      project.save!

      project.create_default_schedule!(created_by: user)
      project.create_default_task_list!(created_by: user)

      after_project_created(project)

      project
    end

    track(action: :create, resource: :project)
    project
  end

  private

  attr_reader :account, :attributes, :user

  def project_attributes
    ProjectAttributes.new(attributes:, user:).to_h
  end

  def after_project_created(project)
    ActiveRecord.after_all_transactions_commit do
      ProjectCreatedWorker.perform_async(project.id)
      ProjectMailer.assigned(project:, assigned_by: user).deliver_later
    end
  end
end
```

Keep one public method on operations unless the object has a real public API.
Put `private`, then grouped readers, then helpers.

## Plain Ruby Objects

When a workflow needs real calculation, mapping, formatting, or branching, push
that logic into small composable Ruby objects. This is the functional core: code
that takes values, returns values, and reads clearly away from Rails side
effects.

```ruby
class ProjectAttributes
  def initialize(attributes:, user:)
    @attributes = attributes
    @user = user
  end

  def to_h
    attributes
      .merge(created_by_id: user.id)
      .compact
  end

  private

  attr_reader :attributes, :user
end
```

```ruby
class ReferenceNumberBuilder
  def initialize(level1:, level2:, level3:, level4:)
    @level1 = level1
    @level2 = level2
    @level3 = level3
    @level4 = level4
  end

  def call
    [
      level1,
      level2,
      level3,
      level4,
    ].compact_blank.join("-")
  end

  private

  attr_reader :level1, :level2, :level3, :level4
end
```

```ruby
class ExternalNameBuilder
  SPECIAL_CHARACTERS = {
    "#" => "number",
    "$" => "dollar",
    "%" => "percent",
  }

  def initialize(name:, prefix:)
    @name = name
    @prefix = prefix
  end

  def call
    return if name.blank?

    name
      .then { |string| handle_special_characters(string) }
      .parameterize
      .then { |string| prepend_if_starts_with_number(string) }
      .underscore
  end

  private

  attr_reader :name, :prefix

  def handle_special_characters(string)
    if string.match?(Regexp.union(SPECIAL_CHARACTERS.keys))
      string.gsub(Regexp.union(SPECIAL_CHARACTERS.keys), SPECIAL_CHARACTERS)
    else
      string
    end
  end

  def prepend_if_starts_with_number(string)
    if string.match?(/\A[0-9]/)
      "#{prefix}#{string}"
    else
      string
    end
  end
end
```

Avoid fake base classes, unused injected dependencies, and abstractions that
only exist because two methods look similar. A small object earns its place when
it names a real concept, isolates deterministic logic, or gives the operation a
cleaner shell around side effects.

## Hard No

- No `OpenStruct`.
- No `yield_self`.
- No inline rescue fallbacks.
- No dense ternaries for domain logic.
- No trailing conditionals for meaningful branches.
- No long safe-navigation chains.
- No broad `rescue` around normal ActiveRecord behavior.

//! Default Cedar schema definitions for the Tanbal stack
//!
//! This module provides the standard Cedar schema used across all Tanbal services.
//! It defines entity types (User, Employee, Project, Task, Workstream, Asset)
//! and actions (View, Create, Edit, Delete, Manage).

/// Default Cedar schema in Cedar's native format, defining all Tanbal entity types and actions.
///
/// Entity hierarchy:
/// - `User` — a human or AI principal identified by JWT subject
/// - `Employee` — an employee record (Human or Ai)
/// - `Project` — a top-level project container
/// - `Workstream` — a sub-grouping within a project
/// - `Task` — a unit of work within a workstream
/// - `Asset` — a generic knowledge/document asset
///
/// Actions:
/// - `View` — read-only access
/// - `Create` — create new resources
/// - `Edit` — modify existing resources
/// - `Delete` — remove resources
/// - `Manage` — administrative operations (assign, archive, status changes)
pub const DEFAULT_CEDAR_SCHEMA: &str = r#"
namespace Tanbal {
    entity User = {
        email?: String,
        role?: String,
        groups?: Set<String>,
        employee_type?: String,
    };

    entity Employee = {
        name: String,
        role: String,
        employee_type: String,
    };

    entity Project = {
        status: String,
        name?: String,
    };

    entity Workstream = {
        status?: String,
        priority?: String,
        name?: String,
    };

    entity Task = {
        status?: String,
        priority?: String,
        assignee?: String,
        project_id?: String,
        workstream_id?: String,
    };

    entity Asset = {
        asset_type?: String,
        status?: String,
        priority?: String,
        scope?: String,
    };

    action View appliesTo {
        principal: [User, Employee],
        resource: [Project, Workstream, Task, Asset],
    };
    action Create appliesTo {
        principal: [User, Employee],
        resource: [Project, Workstream, Task, Asset],
    };
    action Edit appliesTo {
        principal: [User, Employee],
        resource: [Project, Workstream, Task, Asset],
    };
    action Delete appliesTo {
        principal: [User, Employee],
        resource: [Project, Workstream, Task, Asset],
    };
    action Manage appliesTo {
        principal: [User, Employee],
        resource: [Project, Workstream, Task, Asset],
    };
}
"#;

/// Schema using simple entity types without a namespace (for simpler policy authoring)
pub const SIMPLE_CEDAR_SCHEMA: &str = r#"
entity User = {
    email?: String,
    role?: String,
    groups?: Set<String>,
    employee_type?: String,
};

entity Employee = {
    name: String,
    role: String,
    employee_type: String,
};

entity Project = {
    status: String,
    name?: String,
};

entity Workstream = {
    status?: String,
    priority?: String,
    name?: String,
};

entity Task = {
    status?: String,
    priority?: String,
    assignee?: String,
    project_id?: String,
    workstream_id?: String,
};

entity Asset = {
    asset_type?: String,
    status?: String,
    priority?: String,
    scope?: String,
};

action View appliesTo {
    principal: [User, Employee],
    resource: [Project, Workstream, Task, Asset],
};
action Create appliesTo {
    principal: [User, Employee],
    resource: [Project, Workstream, Task, Asset],
};
action Edit appliesTo {
    principal: [User, Employee],
    resource: [Project, Workstream, Task, Asset],
};
action Delete appliesTo {
    principal: [User, Employee],
    resource: [Project, Workstream, Task, Asset],
};
action Manage appliesTo {
    principal: [User, Employee],
    resource: [Project, Workstream, Task, Asset],
};
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_schema_is_valid() {
        let schema: cedar_policy::Schema = DEFAULT_CEDAR_SCHEMA
            .parse()
            .expect("Default Cedar schema should parse successfully");
        // Basic sanity check — schema was constructed without error
        drop(schema);
    }

    #[test]
    fn test_simple_schema_is_valid() {
        let schema: cedar_policy::Schema = SIMPLE_CEDAR_SCHEMA
            .parse()
            .expect("Simple Cedar schema should parse successfully");
        drop(schema);
    }
}

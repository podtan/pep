// ABAC Policies — Attribute-Based Access Control
// These policies use attributes of the principal, action, resource, and context
// to make fine-grained authorization decisions.

// Users can view tasks assigned to them
permit(
    principal == User::"?principal",
    action == Action::"view",
    resource
) when {
    resource.type == "task" &&
    resource has assignee &&
    resource.assignee == principal
};

// Users can view unassigned tasks
permit(
    principal == User::"?principal",
    action == Action::"view",
    resource
) when {
    resource.type == "task" &&
    !(resource has assignee)
};

// Users can edit tasks assigned to them
permit(
    principal == User::"?principal",
    action == Action::"edit",
    resource
) when {
    resource.type == "task" &&
    resource has assignee &&
    resource.assignee == principal
};

// AI employees cannot view blocked tasks
forbid(
    principal in Role::"AiEmployee",
    action == Action::"view",
    resource
) when {
    resource.type == "task" &&
    resource has status &&
    resource.status == "Blocked"
};

// Only managers can change task priority
permit(
    principal in Group::"Managers",
    action == Action::"edit",
    resource
) when {
    resource.type == "task" &&
    resource has status &&
    resource.status != "Completed"
};

// Nobody can delete completed tasks (audit trail)
forbid(
    principal,
    action == Action::"delete",
    resource
) when {
    resource.type == "task" &&
    resource has status &&
    resource.status == "Completed"
};

// Users can only create tasks in projects they belong to
permit(
    principal in Group::"?groupId",
    action == Action::"create",
    resource
) when {
    resource.type == "task"
};

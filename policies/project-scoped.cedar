// Project-scoped permissions
// Members of a project group can view and edit within that project

permit(
    principal in Group::"project-members",
    action in [Action::"view", Action::"edit"],
    resource
) when {
    resource has project_id &&
    principal.groups.contains(resource.project_id)
};

// Project admins can delete within their project
permit(
    principal in Group::"project-admins",
    action == Action::"delete",
    resource
) when {
    resource has project_id &&
    principal.groups.contains(resource.project_id)
};

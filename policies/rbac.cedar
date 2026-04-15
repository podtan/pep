// RBAC Policy: Only admins can delete projects
permit(
    principal in Group::"Admins",
    action == Action::"delete",
    resource == Project::"*"
);

// RBAC Policy: Editors can view and edit
permit(
    principal in Group::"Editors",
    action in [Action::"view", Action::"edit"],
    resource
);

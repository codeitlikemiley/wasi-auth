permit (
    principal is User,
    action == Action::"authorization.check",
    resource is ApplicationResource
) when {
    principal.wasi_permissions.contains(context.requested_action) &&
    (
        (principal.wasi_system_administrator && principal.wasi_assurance == "aal2") ||
        (
            !principal.wasi_system_administrator &&
            principal has wasi_organization_id &&
            resource has wasi_organization_id &&
            principal.wasi_organization_id == resource.wasi_organization_id
        )
    )
};

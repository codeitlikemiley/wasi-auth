permit(
    principal is user,
    action == Action::"document.read",
    resource is document
)
when {
    principal in Role::"employee" &&
    principal.roles.value.contains("reader") &&
    principal.roles.provenance == "identity_provider" &&
    resource.classification.value == "internal" &&
    resource.classification.provenance == "resource_store"
};

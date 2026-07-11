permit(
    principal,
    action == Action::"http.request",
    resource is service
)
when {
    (context.http_method.value == "GET" || context.http_method.value == "HEAD") &&
    context.http_method.provenance == "gateway" &&
    context.http_path.provenance == "gateway"
};

permit(
    principal is principal,
    action == Action::"http.request",
    resource is service
)
when {
    context.http_method.value == "POST" &&
    context.http_method.provenance == "gateway" &&
    context.http_path.value like "/api/*" &&
    context.http_path.provenance == "gateway"
};

permit(
    principal is principal,
    action == Action::"counter.increment",
    resource == counter::"session-counter"
)
when {
    principal.wasi_scopes.contains("write") &&
    principal has roles &&
    principal.roles.value.contains("member") &&
    principal.roles.provenance == "identity_provider" &&
    principal has acr &&
    principal.acr.value == "urn:example:loa:2" &&
    principal.acr.provenance == "identity_provider" &&
    resource.classification.value == "internal" &&
    resource.classification.provenance == "resource_store"
};

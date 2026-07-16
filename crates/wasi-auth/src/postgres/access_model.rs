//! Structured organization permission catalog, dependencies, and custom-role rules.
//!
//! [`OrganizationAccessModel`] is the product source of truth for permission ids,
//! labels, groups, dependency edges, risk, and custom-role eligibility. The flat
//! [`ORGANIZATION_PERMISSION_CATALOG`] id list is derived from the same definitions
//! so SQL seeds and call sites stay aligned.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Risk tier for UI warnings and review flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PermissionRisk {
    /// Read-only or low-impact capability.
    Low,
    /// Mutating capability with moderate blast radius.
    Medium,
    /// High-impact capability (ownership, secret reveal, broad manage).
    High,
}

/// Whether a permission is core tenancy or application-scoped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PermissionCatalog {
    /// Organization, membership, role, ownership, and audit capabilities.
    CoreTenancy,
    /// Product/application capabilities (dashboard, vault, query, …).
    Application,
}

/// One permission in the organization access model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionDefinition {
    /// Stable permission id (matches SQL seed strings).
    pub id: &'static str,
    /// Short human-readable label.
    pub label: &'static str,
    /// Longer description for admin UI.
    pub description: &'static str,
    /// UI grouping label (e.g. `"Members"`, `"Vault"`, `"Core"`).
    pub group: &'static str,
    /// Permission ids that must also be present when this permission is granted.
    pub dependencies: &'static [&'static str],
    /// Relative risk for review surfaces.
    pub risk: PermissionRisk,
    /// Whether custom roles may request this permission.
    pub custom_role_eligible: bool,
    /// Core tenancy vs application catalog split.
    pub catalog: PermissionCatalog,
}

/// Failure while expanding or validating a custom-role permission set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AccessModelError {
    /// Permission id is not in the product catalog.
    UnknownPermission,
    /// Permission is not eligible for custom roles (e.g. `ownership.transfer`).
    RestrictedPermission,
    /// Dependency graph is incomplete after expansion (should not occur for product catalog).
    IncompleteDependencies,
}

impl std::fmt::Display for AccessModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPermission => write!(f, "unknown organization permission"),
            Self::RestrictedPermission => {
                write!(f, "permission is not allowed on custom roles")
            }
            Self::IncompleteDependencies => {
                write!(f, "permission set is missing required dependencies")
            }
        }
    }
}

impl std::error::Error for AccessModelError {}

/// Product organization access model (definitions + validation helpers).
#[derive(Clone, Debug)]
pub struct OrganizationAccessModel {
    definitions: &'static [PermissionDefinition],
}

impl OrganizationAccessModel {
    /// Full product catalog used by the canonical tenant product.
    #[must_use]
    pub const fn product_default() -> Self {
        Self {
            definitions: PRODUCT_DEFINITIONS,
        }
    }

    /// All permission definitions in catalog order (sorted by id).
    #[must_use]
    pub const fn definitions(&self) -> &'static [PermissionDefinition] {
        self.definitions
    }

    /// Sorted permission id slice matching historical catalog call sites.
    #[must_use]
    pub const fn catalog_ids(&self) -> &'static [&'static str] {
        ORGANIZATION_PERMISSION_CATALOG
    }

    /// Looks up one definition by id.
    #[must_use]
    pub fn definition(&self, permission: &str) -> Option<&'static PermissionDefinition> {
        self.definitions.iter().find(|item| item.id == permission)
    }

    /// Whether the permission may appear on a custom role.
    #[must_use]
    pub fn is_allowed_for_custom_role(&self, permission: &str) -> bool {
        self.definition(permission)
            .is_some_and(|item| item.custom_role_eligible)
    }

    /// Expands `permissions` with transitive dependencies, sorted and deduplicated.
    ///
    /// Unknown ids fail closed. Auto-expansion is intentional for custom-role upsert
    /// UX: callers may pass manage-only sets and receive the required view permissions.
    ///
    /// # Errors
    ///
    /// Returns [`AccessModelError::UnknownPermission`] when any input id is absent
    /// from the catalog, or [`AccessModelError::IncompleteDependencies`] if a
    /// declared dependency is missing from the model (catalog integrity failure).
    pub fn expand_with_dependencies(
        &self,
        permissions: &[String],
    ) -> Result<Vec<String>, AccessModelError> {
        let index = self.index();
        let mut expanded = BTreeSet::new();
        let mut queue = VecDeque::new();

        for permission in permissions {
            if !index.contains_key(permission.as_str()) {
                return Err(AccessModelError::UnknownPermission);
            }
            if expanded.insert(permission.clone()) {
                queue.push_back(permission.clone());
            }
        }

        while let Some(current) = queue.pop_front() {
            let definition = index
                .get(current.as_str())
                .ok_or(AccessModelError::IncompleteDependencies)?;
            for dependency in definition.dependencies {
                if !index.contains_key(dependency) {
                    return Err(AccessModelError::IncompleteDependencies);
                }
                let dependency = (*dependency).to_owned();
                if expanded.insert(dependency.clone()) {
                    queue.push_back(dependency);
                }
            }
        }

        Ok(expanded.into_iter().collect())
    }

    /// Validates that every permission is known and custom-role eligible.
    ///
    /// Does not auto-expand; call [`Self::expand_with_dependencies`] first when
    /// incomplete dependency sets should be accepted and filled in.
    ///
    /// # Errors
    ///
    /// Returns [`AccessModelError::UnknownPermission`] or
    /// [`AccessModelError::RestrictedPermission`].
    pub fn validate_custom_role_permissions(
        &self,
        permissions: &[String],
    ) -> Result<(), AccessModelError> {
        for permission in permissions {
            match self.definition(permission) {
                None => return Err(AccessModelError::UnknownPermission),
                Some(definition) if !definition.custom_role_eligible => {
                    return Err(AccessModelError::RestrictedPermission);
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// Ensures the permission set is closed under declared dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`AccessModelError::UnknownPermission`] or
    /// [`AccessModelError::IncompleteDependencies`].
    pub fn ensure_dependencies_present(
        &self,
        permissions: &[String],
    ) -> Result<(), AccessModelError> {
        let present: HashSet<&str> = permissions.iter().map(String::as_str).collect();
        for permission in permissions {
            let definition = self
                .definition(permission)
                .ok_or(AccessModelError::UnknownPermission)?;
            for dependency in definition.dependencies {
                if !present.contains(dependency) {
                    return Err(AccessModelError::IncompleteDependencies);
                }
            }
        }
        Ok(())
    }

    fn index(&self) -> HashMap<&'static str, &'static PermissionDefinition> {
        self.definitions
            .iter()
            .map(|definition| (definition.id, definition))
            .collect()
    }
}

// Single source of truth: ids here drive ORGANIZATION_PERMISSION_CATALOG via the
// matching const below (kept in the same order; tests assert identity).
const PRODUCT_DEFINITIONS: &[PermissionDefinition] = &[
    PermissionDefinition {
        id: "audit.view",
        label: "View audit log",
        description: "Read organization audit events",
        group: "Core",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "counter.change",
        label: "Change counter",
        description: "Increment or adjust the demo counter",
        group: "Counter",
        dependencies: &["counter.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "counter.reset",
        label: "Reset counter",
        description: "Reset the demo counter to zero",
        group: "Counter",
        dependencies: &["counter.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "counter.view",
        label: "View counter",
        description: "Read the demo counter value",
        group: "Counter",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "dashboard.manage",
        label: "Manage dashboard",
        description: "Configure dashboard layout and widgets",
        group: "Dashboard",
        dependencies: &["dashboard.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "dashboard.view",
        label: "View dashboard",
        description: "Open the product dashboard",
        group: "Dashboard",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "member.invite",
        label: "Invite members",
        description: "Create invitations for new members",
        group: "Members",
        dependencies: &["member.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "member.manage",
        label: "Manage members",
        description: "Change member roles and remove members",
        group: "Members",
        dependencies: &["member.view"],
        risk: PermissionRisk::High,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "member.view",
        label: "View members",
        description: "List organization memberships",
        group: "Members",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "organization.update",
        label: "Update organization",
        description: "Change organization display name and settings",
        group: "Core",
        dependencies: &["organization.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "organization.view",
        label: "View organization",
        description: "Read organization profile and metadata",
        group: "Core",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "ownership.transfer",
        label: "Transfer ownership",
        description: "Transfer organization ownership to another member",
        group: "Core",
        dependencies: &[],
        risk: PermissionRisk::High,
        custom_role_eligible: false,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "query.execute",
        label: "Execute queries",
        description: "Run read queries against application data",
        group: "Query",
        dependencies: &["query.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "query.execute_mutation",
        label: "Execute mutations",
        description: "Run mutating queries against application data",
        group: "Query",
        dependencies: &["query.execute"],
        risk: PermissionRisk::High,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "query.manage",
        label: "Manage queries",
        description: "Create and configure saved queries",
        group: "Query",
        dependencies: &["query.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "query.view",
        label: "View queries",
        description: "List and inspect saved queries",
        group: "Query",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "resource.manage",
        label: "Manage resources",
        description: "Create, update, and delete resources",
        group: "Resources",
        dependencies: &["resource.view"],
        risk: PermissionRisk::Medium,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "resource.view",
        label: "View resources",
        description: "List and inspect resources",
        group: "Resources",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "role.manage",
        label: "Manage roles",
        description: "Create and update custom roles",
        group: "Roles",
        dependencies: &["role.view"],
        risk: PermissionRisk::High,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "role.view",
        label: "View roles",
        description: "List roles and their permissions",
        group: "Roles",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::CoreTenancy,
    },
    PermissionDefinition {
        id: "vault.manage",
        label: "Manage vault",
        description: "Create and update vault secrets metadata",
        group: "Vault",
        dependencies: &["vault.view"],
        risk: PermissionRisk::High,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "vault.reveal",
        label: "Reveal vault secrets",
        description: "Reveal secret values from the vault",
        group: "Vault",
        dependencies: &["vault.view"],
        risk: PermissionRisk::High,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
    PermissionDefinition {
        id: "vault.view",
        label: "View vault",
        description: "List vault entries without revealing values",
        group: "Vault",
        dependencies: &[],
        risk: PermissionRisk::Low,
        custom_role_eligible: true,
        catalog: PermissionCatalog::Application,
    },
];

/// Permissions available to tenant roles in the canonical product.
///
/// Ids match [`OrganizationAccessModel::product_default`] definitions (sorted).
pub const ORGANIZATION_PERMISSION_CATALOG: &[&str] = &[
    "audit.view",
    "counter.change",
    "counter.reset",
    "counter.view",
    "dashboard.manage",
    "dashboard.view",
    "member.invite",
    "member.manage",
    "member.view",
    "organization.update",
    "organization.view",
    "ownership.transfer",
    "query.execute",
    "query.execute_mutation",
    "query.manage",
    "query.view",
    "resource.manage",
    "resource.view",
    "role.manage",
    "role.view",
    "vault.manage",
    "vault.reveal",
    "vault.view",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> OrganizationAccessModel {
        OrganizationAccessModel::product_default()
    }

    #[test]
    fn catalog_matches_definitions_and_is_sorted_unique() {
        let ids: Vec<&str> = model().definitions().iter().map(|item| item.id).collect();
        assert_eq!(ids.as_slice(), ORGANIZATION_PERMISSION_CATALOG);
        assert!(
            ORGANIZATION_PERMISSION_CATALOG
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert_eq!(
            ORGANIZATION_PERMISSION_CATALOG.len(),
            ORGANIZATION_PERMISSION_CATALOG
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
        );
    }

    #[test]
    fn core_and_application_split_covers_catalog() {
        let mut core = 0;
        let mut application = 0;
        for definition in model().definitions() {
            match definition.catalog {
                PermissionCatalog::CoreTenancy => core += 1,
                PermissionCatalog::Application => application += 1,
            }
        }
        assert!(core >= 8, "expected core tenancy permissions, got {core}");
        assert!(
            application >= 10,
            "expected application permissions, got {application}"
        );
        assert_eq!(core + application, ORGANIZATION_PERMISSION_CATALOG.len());

        for id in [
            "organization.view",
            "organization.update",
            "member.view",
            "member.invite",
            "member.manage",
            "role.view",
            "role.manage",
            "ownership.transfer",
            "audit.view",
        ] {
            assert_eq!(
                model().definition(id).unwrap().catalog,
                PermissionCatalog::CoreTenancy,
                "{id}"
            );
        }
        for id in [
            "dashboard.view",
            "dashboard.manage",
            "counter.view",
            "counter.change",
            "counter.reset",
            "resource.view",
            "resource.manage",
            "query.view",
            "query.manage",
            "query.execute",
            "query.execute_mutation",
            "vault.view",
            "vault.manage",
            "vault.reveal",
        ] {
            assert_eq!(
                model().definition(id).unwrap().catalog,
                PermissionCatalog::Application,
                "{id}"
            );
        }
    }

    #[test]
    fn ownership_transfer_is_not_custom_role_eligible() {
        assert!(!model().is_allowed_for_custom_role("ownership.transfer"));
        assert!(
            model()
                .validate_custom_role_permissions(&["ownership.transfer".into()])
                .is_err()
        );
    }

    #[test]
    fn expand_adds_manage_view_dependencies() {
        let expanded = model()
            .expand_with_dependencies(&[
                "member.manage".into(),
                "member.invite".into(),
                "role.manage".into(),
                "vault.reveal".into(),
                "vault.manage".into(),
                "dashboard.manage".into(),
                "resource.manage".into(),
                "organization.update".into(),
            ])
            .unwrap();
        for required in [
            "member.view",
            "role.view",
            "vault.view",
            "dashboard.view",
            "resource.view",
            "organization.view",
        ] {
            assert!(
                expanded.iter().any(|item| item == required),
                "missing {required} in {expanded:?}"
            );
        }
    }

    #[test]
    fn expand_query_execute_mutation_pulls_execute_and_view() {
        let expanded = model()
            .expand_with_dependencies(&["query.execute_mutation".into()])
            .unwrap();
        assert_eq!(
            expanded,
            vec![
                "query.execute".to_owned(),
                "query.execute_mutation".to_owned(),
                "query.view".to_owned(),
            ]
        );
    }

    #[test]
    fn expand_rejects_unknown_permission() {
        assert_eq!(
            model().expand_with_dependencies(&["not.a.permission".into()]),
            Err(AccessModelError::UnknownPermission)
        );
    }

    #[test]
    fn validate_rejects_unknown_and_allows_eligible() {
        assert_eq!(
            model().validate_custom_role_permissions(&["nope".into()]),
            Err(AccessModelError::UnknownPermission)
        );
        assert!(
            model()
                .validate_custom_role_permissions(&["member.view".into(), "dashboard.view".into()])
                .is_ok()
        );
    }

    #[test]
    fn ensure_dependencies_detects_incomplete_sets() {
        assert_eq!(
            model().ensure_dependencies_present(&["member.manage".into()]),
            Err(AccessModelError::IncompleteDependencies)
        );
        let expanded = model()
            .expand_with_dependencies(&["member.manage".into()])
            .unwrap();
        assert!(model().ensure_dependencies_present(&expanded).is_ok());
    }

    #[test]
    fn dependency_edges_only_reference_catalog_ids() {
        let ids: HashSet<&str> = ORGANIZATION_PERMISSION_CATALOG.iter().copied().collect();
        for definition in model().definitions() {
            for dependency in definition.dependencies {
                assert!(
                    ids.contains(dependency),
                    "{} depends on unknown {}",
                    definition.id,
                    dependency
                );
            }
        }
    }
}

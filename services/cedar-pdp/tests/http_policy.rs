//! End-to-end checks for the checked-in coarse HTTP Cedar policy.

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use wasi_authz_cedar_pdp::CedarPdp;
use wasi_authz_contract::{
    ACCESS_EVALUATION_PATH, AccessEvaluation, Action, AttributeNameV1, AttributeProvenanceV1,
    AttributeStringListV1, AttributeStringV1, AttributeV1, AttributeValueV1, AttributesV1,
    AuthenticatedSubjectV1, ContextV1, DecisionResponseV1, EntityIdV1, EntityTypeV1, IssuerV1,
    Resource, ScopeV1, SubjectV1,
};

const POLICY: &str = include_str!("../../../fixtures/cedar/http_policy.cedar");
const SCHEMA: &str = include_str!("../../../fixtures/cedar/http_schema.json");
const ENTITIES: &str = include_str!("../../../fixtures/cedar/http_entities.json");

#[test]
fn reference_http_policy_separates_public_and_protected_routes() {
    let pdp = CedarPdp::new_validated(POLICY, SCHEMA, ENTITIES, "http-policy-1", "cedar-4.11.2")
        .expect("reference HTTP policy strictly activates");

    assert!(decision(&pdp, evaluation(SubjectV1::Anonymous, "GET", "/")).is_allowed());
    assert!(
        decision(
            &pdp,
            evaluation(SubjectV1::Anonymous, "GET", "/pkg/app.wasm")
        )
        .is_allowed()
    );
    assert!(
        domain_decision(
            &pdp,
            authenticated_subject_with_claims(["write"], ["member"], "urn:example:loa:2"),
            "session-counter"
        )
        .is_allowed()
    );
    assert!(domain_decision(&pdp, authenticated_subject([]), "session-counter").is_denied());
    assert!(
        decision(
            &pdp,
            evaluation(SubjectV1::Anonymous, "POST", "/api/increment_count")
        )
        .is_denied()
    );
    assert!(
        decision(
            &pdp,
            evaluation(authenticated_subject([]), "POST", "/api/increment_count")
        )
        .is_allowed()
    );
    assert!(
        decision(
            &pdp,
            evaluation(
                authenticated_subject(["read"]),
                "POST",
                "/api/increment_count"
            )
        )
        .is_allowed()
    );
}

fn evaluation(subject: SubjectV1, method: &str, path: &str) -> AccessEvaluation {
    AccessEvaluation::new(
        subject,
        Action::new("http.request").expect("valid fixture"),
        Resource::new("service", "leptos-wasi-counter").expect("valid fixture"),
    )
    .with_context(
        ContextV1::new().with_attributes(
            AttributesV1::try_from_vec(vec![
                string_attribute("http_method", method),
                string_attribute("http_path", path),
            ])
            .expect("valid fixture"),
        ),
    )
}

fn authenticated_subject<const N: usize>(scopes: [&str; N]) -> SubjectV1 {
    let scopes = scopes
        .into_iter()
        .map(|scope| ScopeV1::new(scope).expect("valid fixture"))
        .collect();
    SubjectV1::Authenticated(
        AuthenticatedSubjectV1::new(
            EntityTypeV1::new("principal").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new("https://identity.example").expect("valid fixture"),
        )
        .with_scopes(scopes)
        .expect("valid fixture"),
    )
}

fn authenticated_subject_with_claims<const N: usize, const M: usize>(
    scopes: [&str; N],
    roles: [&str; M],
    acr: &str,
) -> SubjectV1 {
    let SubjectV1::Authenticated(subject) = authenticated_subject(scopes) else {
        panic!("fixture must be authenticated");
    };
    let roles = roles
        .into_iter()
        .map(|role| AttributeStringV1::new(role).expect("valid fixture"))
        .collect();
    let roles = AttributeV1::new(
        AttributeNameV1::new("roles").expect("valid fixture"),
        AttributeValueV1::StringList(
            AttributeStringListV1::new(roles).expect("valid fixture roles"),
        ),
        AttributeProvenanceV1::IdentityProvider,
    )
    .expect("valid fixture role attribute");
    let acr = AttributeV1::new(
        AttributeNameV1::new("acr").expect("valid fixture"),
        AttributeValueV1::String(AttributeStringV1::new(acr).expect("valid fixture")),
        AttributeProvenanceV1::IdentityProvider,
    )
    .expect("valid fixture ACR attribute");
    SubjectV1::Authenticated(subject.with_attributes(
        AttributesV1::try_from_vec(vec![roles, acr]).expect("valid fixture attributes"),
    ))
}

fn string_attribute(name: &str, value: &str) -> AttributeV1 {
    AttributeV1::new(
        AttributeNameV1::new(name).expect("valid fixture"),
        AttributeValueV1::String(AttributeStringV1::new(value).expect("valid fixture")),
        AttributeProvenanceV1::Gateway,
    )
    .expect("valid fixture")
}

fn decision(pdp: &CedarPdp, evaluation: AccessEvaluation) -> DecisionResponseV1 {
    let body = evaluation.to_json_vec().expect("evaluation encodes");
    let response = pdp.handle(
        Request::builder()
            .method(Method::POST)
            .uri(ACCESS_EVALUATION_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .expect("request builds"),
    );
    assert_eq!(response.status(), StatusCode::OK);
    DecisionResponseV1::from_json_slice(response.body()).expect("decision decodes")
}

fn domain_decision(pdp: &CedarPdp, subject: SubjectV1, resource_id: &str) -> DecisionResponseV1 {
    decision(
        pdp,
        AccessEvaluation::new(
            subject,
            Action::new("counter.increment").expect("valid fixture"),
            Resource::new("counter", resource_id)
                .expect("valid fixture")
                .with_attributes(
                    AttributesV1::try_from_vec(vec![
                        AttributeV1::new(
                            AttributeNameV1::new("classification").expect("valid fixture"),
                            AttributeValueV1::String(
                                AttributeStringV1::new("internal").expect("valid fixture"),
                            ),
                            AttributeProvenanceV1::ResourceStore,
                        )
                        .expect("valid fixture"),
                    ])
                    .expect("valid fixture attributes"),
                ),
        ),
    )
}

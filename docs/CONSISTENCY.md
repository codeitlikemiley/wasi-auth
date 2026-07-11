# Relationship mutation consistency

SpiceDB consistency tokens are an application invariant, not an automatic
cross-database transaction supplied by this workspace. The application must
carry the protected resource revision and authorization consistency token
through its transaction/outbox workflow.

For a relationship-changing mutation:

1. Load the authoritative resource and its current revision/token, then perform
   the domain authorization check immediately before the write.
2. In one application-database transaction, write the domain mutation and a
   uniquely identified relationship outbox intent containing the same protected
   resource revision. Never put credentials or identity envelopes in the event.
3. An idempotent worker applies the relationship mutation to SpiceDB and records
   the returned ZedToken.
4. In a second application-database transaction, conditionally attach that token
   to the matching protected resource revision and mark the outbox intent
   complete. A revision mismatch retries or supersedes the intent; it must not
   attach the token to different resource state.
5. Subsequent authorization requests for that resource use
   `at_least_as_fresh` with the stored token. The token returned by the decision
   is carried forward with any newer protected resource revision.

Security-reducing operations such as revocation must fail closed while their
relationship intent is pending; otherwise a stale read could preserve access.
Grant operations must not advertise the new access before SpiceDB confirms the
write. Retries use the outbox identity to remain idempotent, and indeterminate or
expired workflows require operator recovery rather than falling back to
minimize-latency reads.

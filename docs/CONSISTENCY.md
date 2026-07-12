# Relationship mutation consistency

SpiceDB consistency tokens are an application invariant, not an automatic
cross-database transaction supplied by this workspace. The application must
carry the protected resource revision and authorization consistency token
through its transaction/outbox workflow.

For a relationship-changing mutation:

1. Lock the authoritative organization and perform the domain authorization
   and last-owner checks immediately before the write.
2. The PostgreSQL membership trigger increments the authorization revision and
   inserts a uniquely identified, typed relationship intent in the same
   transaction. Tokens and credentials never enter relationship metadata.
3. An idempotent worker applies the relationship mutation to SpiceDB and records
   the returned ZedToken.
4. The worker conditionally completes the leased intent with that ZedToken.
   Grant and revoke rows for the same tuple are leased in revision order.
5. Subsequent authorization requests for that resource use
   `at_least_as_fresh` with the stored token. The token returned by the decision
   is carried forward with any newer protected resource revision.

Security-reducing operations such as revocation fail closed while that
resource has a pending, leased, or dead-letter intent; otherwise a stale read
could preserve access. Grant operations do not advertise new access before
SpiceDB confirms the write. Retries use idempotent `TOUCH`/`DELETE` operations,
and indeterminate or expired workflows require operator recovery rather than
falling back to minimize-latency reads. Unrelated resources remain available.

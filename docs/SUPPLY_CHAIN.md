# Supply-chain artifacts

`scripts/build-components.sh`, `build-native-pdp.sh`, checksum generators,
`generate-sbom.sh`, and `check-component-contracts.sh` produce the local
release inputs. The repository tracks normalized CycloneDX 1.5 SBOMs, portable
WASM SHA-256 metadata, and exact WIT reports. The native Cedar PDP is named and
checksummed with its Rust target triple so artifacts from different operating
systems cannot be confused. `check-native-reproducibility.sh` performs a clean
second package build and requires the target-qualified binary digest to match.

`scripts/dry-run-supply-chain.sh` then:

1. verifies every component and target-qualified native checksum;
2. emits deterministic SLSA v1/in-toto provenance including the authz and
   middleware source revisions, `Cargo.lock`, compatibility lock, and WIT lock;
3. creates a local OCI layout with the component, WIT, checksums, SBOMs, and
   provenance; and
4. generates an ephemeral cosign key, signs both provenance and the OCI
   manifest, and verifies both signatures.

The dry run never contacts an OCI registry and deliberately deletes its private
key. It proves artifact assembly and signature verification, but it is not a
published identity. A real release must use an authorized CI identity or
protected release key, attach the same subjects to the immutable OCI digest,
publish transparency/provenance evidence, and verify it after registry pull.

No script in this repository pushes, tags, or publishes.

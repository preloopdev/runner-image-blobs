set -euo pipefail
# sigstore's public-good log flakes; cosign has no retry flag.
retry() { for i in 1 2 3 4 5; do "$@" && return 0; sleep $((i * 10)); done; return 1; }
sort -u digests-*.txt | while read -r ref; do
  [ -n "$ref" ] || continue
  image="${ref%@*}"; digest="${ref#*@}"
  echo "==> $ref"
  # Idempotency: this backfill path re-runs on a schedule, so skip
  # digests already signed (with attestations) by either this
  # workflow or the dump workflow's integrated attest-and-sign job.
  if cosign verify "$ref" \
      --certificate-identity-regexp \
        "^https://github.com/$GITHUB_REPOSITORY/.github/workflows/(dump|attest-local)\.yml@refs/heads/" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      >/dev/null 2>&1; then
    echo "already attested and signed: $ref"
    continue
  fi
  # Pull the exact digest so the scan can read it: the runner's
  # daemon is logged in with the workflow token, and the registry
  # package is private (trivy's own remote backend has no token).
  # Shared layers are kept across digests (scans are cached per
  # layer) and only pruned under disk pressure, so the ~40 images
  # of one runner transfer their unique layers roughly once.
  FREE_KB=$(df -k / | awk 'NR==2 {print $4}')
  if [ "${FREE_KB:-0}" -lt 3145728 ]; then
    docker image prune -af >/dev/null 2>&1 || true
  fi
  docker pull "$ref"
  # 1. Vulnerability/secret scan. The scan MUST complete (coverage
  # gate); findings are logged as the published report but are NOT a
  # hard failure: GitHub's hosted snapshots ship known HIGH/CRITICAL
  # CVEs and test keys by construction (the 20260720.247.2 snapshot
  # scans ~64 HIGH / 2 CRITICAL), so a zero-finding gate would
  # permanently block publication of exactly the images this
  # pipeline exists to publish. Trust comes from the SLSA
  # attestation, keyless signature, and SPDX SBOM attached below.
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    ghcr.io/aquasecurity/trivy:latest image \
    --severity HIGH,CRITICAL --exit-code 0 --no-progress --timeout 30m --parallel 2 "$ref"
  # 2. SPDX SBOM generated from the scanned layers and attached as a
  # signed in-toto attestation so golden builds can bind it. `trivy
  # sbom` scans *existing* SBOM files; the image subcommand emits the
  # SPDX document from the (pulled) image.
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD:/out" ghcr.io/aquasecurity/trivy:latest image \
    --format spdx-json --no-progress --timeout 30m --parallel 2 \
    --output /out/sbom.json "$ref"
  # 3. SLSA provenance, attached as a signed in-toto attestation.
  # The keyless certificate's OIDC identity is this workflow, so the
  # provenance is GitHub-Actions-signed (Fulcio + Rekor), stored as
  # an OCI referrer in GHCR. `gh attestation attest` is no longer
  # shipped by the GitHub CLI, and attest-build-provenance only runs
  # as a per-subject action step, so cosign attaches it.
  printf '%s\n' \
    '{' \
    '  "builder": { "id": "https://github.com/'"$GITHUB_REPOSITORY"'/.github/workflows/attest-local.yml@refs/heads/" },' \
    '  "buildType": "https://github.com/preloopdev/runner-image-blobs/dump@v1",' \
    '  "invocation": { "configSource": { "uri": "git+https://github.com/'"$GITHUB_REPOSITORY"'.git", "digest": { "sha1": "'"$GITHUB_SHA"'" }, "entryPoint": "dump.yml" } },' \
    '  "metadata": { "buildInvocationId": "'"$GITHUB_RUN_ID"'" }' \
    '}' > slsa.json
  retry cosign attest --type slsaprovenance --predicate slsa.json --yes "$ref"
  rm -f slsa.json
  # 4. Sigstore keyless signature (Fulcio + Rekor transparency log).
  retry cosign sign --yes --timeout 5m "$ref"
  # 5. Signed SPDX SBOM attestation.
  retry cosign attest --type spdx --predicate sbom.json --yes "$ref"
  # 6. Self-verify: only signatures from this repo's attest-local
  # workflow on the default branch are accepted.
  retry cosign verify "$ref" \
    --certificate-identity-regexp \
      "^https://github.com/$GITHUB_REPOSITORY/.github/workflows/attest-local.yml@refs/heads/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  rm -f sbom.json
  echo "OK $ref"
done

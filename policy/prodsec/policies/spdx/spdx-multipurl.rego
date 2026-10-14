# METADATA
# title: SPDX SBOM Contains Multiple PURLs
# description: >-
#   SPDX counterpart of CDX_MULTIPURL. CycloneDX 1.6 lists PURL aliases in .evidence.identity; SPDX lists every PURL as its own externalRef.
# custom:
#   short_name: SPDX_MULTIPURL
#   severity: tip
package prodsec.policies.spdx.SPDX_MULTIPURL

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
	# same gate as the CycloneDX rule's 1.6 (where evidence.identity was added)
	semver.compare(spdx_util.spdx_semver, "2.3.0") >= 0
}

_policy_id := "SPDX_MULTIPURL"

# METADATA
# title: SPDX SBOM Uses Multi-PURL
# description: A given SBOM has a package with more than one purl externalRef.
# custom:
#   short_name: spdx_contains_multipurl_example
#   failure_msg: TIP == SPDX can represent PURL aliases by adding one purl externalRef per PURL to a package. This is supported for Trustify SBOM ingestion.
#   severity: tip
deny contains result if {
	prerequisite
	count([p | some p in object.get(input, "packages", []); count(spdx_util.refs_of_type(p, {"purl"})) > 1]) == 0
	example_snippet := {"externalRefs": [
		{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "main_purl_here"},
		{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "purl_alias_here"},
	]}
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id, "multipurl_example": example_snippet},
	)
}

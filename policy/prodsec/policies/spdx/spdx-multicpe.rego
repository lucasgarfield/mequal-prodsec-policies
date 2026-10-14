# METADATA
# title: SPDX SBOM Contains Multiple CPEs
# description: >-
#   SPDX counterpart of CDX_MULTICPE. CycloneDX 1.6 lists CPE aliases in metadata.component.evidence.identity; SPDX lists every CPE as its own externalRef on the described package.
# custom:
#   short_name: SPDX_MULTICPE
#   severity: tip
package prodsec.policies.spdx.SPDX_MULTICPE

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
	# same gate as the CycloneDX rule's 1.6 (where evidence.identity was added)
	semver.compare(spdx_util.spdx_semver, "2.3.0") >= 0
	some p in spdx_util.described_packages
	count(spdx_util.refs_of_type(p, spdx_util.cpe_types)) > 0
}

_policy_id := "SPDX_MULTICPE"

# METADATA
# title: SPDX SBOM Uses Multi-CPE
# description: A package the SPDX document describes has more than one CPE externalRef.
# custom:
#   short_name: spdx_contains_multicpe_example
#   failure_msg: TIP == This SBOM includes a main CPE. SPDX can represent CPE aliases by adding one externalRef per CPE to the described package. This is supported for Trustify SBOM ingestion.
#   severity: tip
deny contains result if {
	prerequisite
	count([p | some p in spdx_util.described_packages; count(spdx_util.refs_of_type(p, spdx_util.cpe_types)) > 1]) == 0
	example_snippet := {"externalRefs": [
		{"referenceCategory": "SECURITY", "referenceType": "cpe22Type", "referenceLocator": "main_cpe_here"},
		{"referenceCategory": "SECURITY", "referenceType": "cpe22Type", "referenceLocator": "cpe_alias_here"},
	]}
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id, "multi_cpe_example": example_snippet},
	)
}

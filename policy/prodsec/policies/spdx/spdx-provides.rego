# METADATA
# title: SPDX SBOM Uses Source-to-Binary Relationships
# description: >-
#   SPDX counterpart of CDX_PROVIDES for its Trustify use, source-to-binary links, which SPDX 2.3 expresses with GENERATED_FROM / GENERATES relationships.
# custom:
#   short_name: SPDX_PROVIDES
#   severity: tip
package prodsec.policies.spdx.SPDX_PROVIDES

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_PROVIDES"

# METADATA
# title: Source-to-Binary Relationships are Used in SPDX SBOM
# description: In a given SPDX SBOM, there are GENERATED_FROM or GENERATES relationships.
# custom:
#   short_name: spdx_generated_from_relationships_are_used
#   failure_msg: TIP == In this SBOM, GENERATED_FROM / GENERATES relationships have not been utilized. If the SBOM is to be ingested by Trustify, they specify source-to-binary relationships.
#   severity: tip
deny contains result if {
	prerequisite
	count(spdx_util.relationships_of_type({"GENERATED_FROM", "GENERATES"})) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

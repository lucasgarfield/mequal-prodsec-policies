# METADATA
# title: SPDX SBOM Uses Ancestor Relationships
# description: >-
#   SPDX counterpart of CDX_ANCESTORS. CycloneDX nests the upstream of a component in pedigree.ancestors; SPDX 2.3 expresses the same with ANCESTOR_OF / DESCENDANT_OF relationships.
# custom:
#   short_name: SPDX_ANCESTORS
#   severity: tip
package prodsec.policies.spdx.SPDX_ANCESTORS

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_ANCESTORS"

# METADATA
# title: Ancestor Relationships are Used in SPDX SBOM
# description: In a given SPDX SBOM, there are ANCESTOR_OF or DESCENDANT_OF relationships.
# custom:
#   short_name: spdx_ancestor_relationships_are_used
#   failure_msg: TIP == In this SBOM, ANCESTOR_OF / DESCENDANT_OF relationships have not been utilized. They can denote the upstream of a package.
#   severity: tip
deny contains result if {
	prerequisite
	count(spdx_util.relationships_of_type({"ANCESTOR_OF", "DESCENDANT_OF"})) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

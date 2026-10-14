# METADATA
# title: SPDX SBOM Uses Variant Relationships
# description: >-
#   SPDX counterpart of CDX_VARIANTS. CycloneDX nests architecture variants in pedigree.variants; SPDX 2.3 expresses the same with VARIANT_OF relationships.
# custom:
#   short_name: SPDX_VARIANTS
#   severity: tip
package prodsec.policies.spdx.SPDX_VARIANTS

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_VARIANTS"

# METADATA
# title: Variant Relationships are Used in SPDX SBOM
# description: In a given SPDX SBOM, there are VARIANT_OF relationships.
# custom:
#   short_name: spdx_variant_relationships_are_used
#   failure_msg: TIP == In this SBOM, VARIANT_OF relationships have not been utilized. They can represent the relationship of an image index to its architecture variants.
#   severity: tip
deny contains result if {
	prerequisite
	count(spdx_util.relationships_of_type({"VARIANT_OF"})) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

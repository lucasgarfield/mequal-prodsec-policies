# METADATA
# title: SPDX SBOM has a Main CPE
# description: >-
#   SPDX counterpart of CDX_CPE. SPDX has no .metadata.component.cpe; a CPE is a SECURITY externalRef (cpe22Type / cpe23Type) on the described package.
# custom:
#   short_name: SPDX_CPE
#   severity: tip
package prodsec.policies.spdx.SPDX_CPE

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_CPE"

# METADATA
# title: SPDX SBOM Has CPE
# description: A package the SPDX document describes has a CPE externalRef.
# custom:
#   short_name: spdx_main_package_has_cpe
#   failure_msg: TIP == If this a product-level SBOM, it is advised to define a CPE externalRef (cpe22Type or cpe23Type) on the described package to directly tie it to that product. If this is a component-level SBOM please disregard this tip.
#   severity: tip
deny contains result if {
	prerequisite
	count([p | some p in spdx_util.described_packages; count(spdx_util.refs_of_type(p, spdx_util.cpe_types)) > 0]) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

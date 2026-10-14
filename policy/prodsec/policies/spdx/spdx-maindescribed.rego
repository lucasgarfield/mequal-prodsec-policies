# METADATA
# title: SPDX_MAINPACKAGE
# description: >-
#   SPDX counterpart of CDX_MAINCOMPONENTDUP. SPDX has no separate .metadata.component to duplicate; the described package must itself be present in packages[].
# custom:
#   short_name: SPDX_MAINPACKAGE
#   severity: error
package prodsec.policies.spdx.SPDX_MAINPACKAGE

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_MAINPACKAGE"

# METADATA
# title: Described package is in packages
# description: Every SPDX ID the document describes is a package in packages[].
# custom:
#   short_name: spdx_described_package_in_packages
#   failure_msg: SPDX SBOM describes '%s', which is not in the packages array
#   severity: error
deny contains result if {
	prerequisite
	some id in spdx_util.described_ids
	not startswith(id, "DocumentRef-")
	count([p | some p in object.get(input, "packages", []); p.SPDXID == id]) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [id]),
		{"policy_id": _policy_id},
	)
}

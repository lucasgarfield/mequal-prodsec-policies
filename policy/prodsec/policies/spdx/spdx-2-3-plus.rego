# METADATA
# title: Teams should use SPDX 2.3 and above to use key features
# description: >-
#   SPDX counterpart of CDX_1_6_PLUS. SPDX 2.3 is the newest 2.x version and the one the Red Hat SBOM guide and Trustify target.
# custom:
#   short_name: SPDX_2_3_PLUS
#   severity: tip
package prodsec.policies.spdx.SPDX_2_3_PLUS

import data.ec.lib
import data.ec.lib.util.is_spdx
import data.prodsec.spdx_util
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_2_3_PLUS"

# METADATA
# title: SBOM is SPDX 2.3 and Above
# description: SBOM is SPDX 2.3 and above in order to ensure support of potentially important features.
# custom:
#   short_name: spdx_sbom_is_spdx_2_3_and_above
#   failure_msg: The SPDX version of this SBOM is older than SPDX-2.3, which may not support important features that may be required for complete and accurate manifesting.
#   severity: tip
deny contains result if {
	prerequisite
	not _is_2_3_or_above
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

_is_2_3_or_above if semver.compare(spdx_util.spdx_semver, "2.3.0") >= 0

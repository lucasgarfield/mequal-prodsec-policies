# METADATA
# title: Specify the SBOM Type in SPDX
# description: >-
#   SPDX counterpart of CDX_SBOMTYPE. SPDX 2.3 has no field for the SBOM type (CycloneDX .metadata.lifecycles; SPDX 3.0 software_sbomType), so this checks creationInfo.comment for "SBOM type: <CISA type>".
# custom:
#   short_name: SPDX_SBOMTYPE
#   severity: warning
package prodsec.policies.spdx.SPDX_SBOMTYPE

import data.ec.lib
import data.ec.lib.util.is_spdx
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_SBOMTYPE"

# METADATA
# title: SPDX creationInfo.comment Declares the SBOM Type
# description: In an SPDX SBOM, creationInfo.comment contains "SBOM type:" followed by a CISA SBOM type (design, source, build, analyzed, deployed, runtime).
# custom:
#   short_name: spdx_creationinfo_sbom_type_exists
#   failure_msg: No "SBOM type:" declaration has been found in creationInfo.comment. Defining an SBOM type helps Mequal evaluate SBOMs in different specialized contexts in the future.
#   severity: warning
deny contains result if {
	prerequisite
	not regex.match(`(?i)\bsbom type:\s*(design|source|build|analyzed|deployed|runtime)\b`, object.get(object.get(input, "creationInfo", {}), "comment", ""))
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

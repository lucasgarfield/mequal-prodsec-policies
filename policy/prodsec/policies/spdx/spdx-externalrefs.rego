# METADATA
# title: SPDX SBOM Makes Valid External References to other SBOMs
# description: >-
#   SPDX counterpart of CDX_EXTERNALREFS. CycloneDX references other SBOMs from components (Bomlink urn:cdx: or a bom URL); SPDX 2.3 declares them once in externalDocumentRefs (DocumentRef- ID, spdxDocument URI, SHA1 checksum).
# custom:
#   short_name: SPDX_EXTERNALREFS
#   severity: error
package prodsec.policies.spdx.SPDX_EXTERNALREFS

import data.ec.lib
import data.ec.lib.util.is_spdx
import rego.v1

prerequisite if {
	is_spdx
}

_policy_id := "SPDX_EXTERNALREFS"

_doc_refs := object.get(input, "externalDocumentRefs", [])

# METADATA
# title: All External Document References are Valid
# description: Given an SBOM, ensure that every externalDocumentRefs entry has a valid DocumentRef- ID and a SHA1 checksum.
# custom:
#   short_name: spdx_all_sbom_exrefs_valid_documentref
#   failure_msg: An invalid external document reference has been found for externalDocumentIds %s
#   severity: error
deny contains result if {
	prerequisite
	count(_invalid_ids) > 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [_invalid_ids]),
		{"policy_id": _policy_id},
	)
}

_invalid_ids contains object.get(ref, "externalDocumentId", "") if {
	some ref in _doc_refs
	not _valid(ref)
}

_valid(ref) if {
	regex.match(`^DocumentRef-[A-Za-z0-9.\-]+$`, ref.externalDocumentId)
	ref.checksum.algorithm == "SHA1"
	regex.match(`^[0-9a-f]{40}$`, ref.checksum.checksumValue)
}

# METADATA
# title: All External Document References Have Non-empty spdxDocument Fields
# description: Given an SBOM, ensure that every externalDocumentRefs entry has a non-empty spdxDocument URI.
# custom:
#   short_name: spdx_all_sbom_exrefs_nonempty_spdxdocument
#   failure_msg: An empty spdxDocument has been found for externalDocumentIds %s
#   severity: error
deny contains result if {
	prerequisite
	count(_empty_ids) > 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [_empty_ids]),
		{"policy_id": _policy_id},
	)
}

_empty_ids contains object.get(ref, "externalDocumentId", "") if {
	some ref in _doc_refs
	object.get(ref, "spdxDocument", "") == ""
}

# METADATA
# title: External SBOM References Used
# description: Given an SBOM, there have been external document references identified.
# custom:
#   short_name: spdx_sbom_exrefs_used
#   failure_msg: TIP == No external SBOM references have been found in this SBOM. Referencing other SBOMs is possible with externalDocumentRefs.
#   severity: tip
deny contains result if {
	prerequisite
	count(_doc_refs) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{"policy_id": _policy_id},
	)
}

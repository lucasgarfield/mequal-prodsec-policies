package prodsec.spdx_util

import rego.v1

# SPDX IDs of the packages the document describes (the SPDX counterpart of
# CycloneDX .metadata.component): documentDescribes, DESCRIBES from the
# document, and DESCRIBED_BY pointing at the document.
described_ids contains id if {
	some id in input.documentDescribes
}

described_ids contains r.relatedSpdxElement if {
	some r in input.relationships
	r.spdxElementId == "SPDXRef-DOCUMENT"
	r.relationshipType == "DESCRIBES"
}

described_ids contains r.spdxElementId if {
	some r in input.relationships
	r.relatedSpdxElement == "SPDXRef-DOCUMENT"
	r.relationshipType == "DESCRIBED_BY"
}

described_packages contains p if {
	some p in input.packages
	p.SPDXID in described_ids
}

refs_of_type(pkg, types) := [ref |
	some ref in object.get(pkg, "externalRefs", [])
	ref.referenceType in types
]

cpe_types := {"cpe22Type", "cpe23Type"}

relationships_of_type(types) := [r |
	some r in object.get(input, "relationships", [])
	r.relationshipType in types
]

# "SPDX-2.3" -> "2.3.0"
spdx_semver := v if {
	m := regex.find_all_string_submatch_n(`^SPDX-(\d+)\.(\d+)$`, input.spdxVersion, 1)[0]
	v := sprintf("%s.%s.0", [m[1], m[2]])
}

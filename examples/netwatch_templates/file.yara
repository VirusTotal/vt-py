rule network_watch_${domain_escaped} : domain_${domain_escaped} {
meta:
  description = "New files downloaded from ${domain}"
  target_entity = "file"
condition:
  vt.metadata.new_file and
  vt.metadata.itw.domain.root == "${domain}"
}


rule network_watch_contact_${domain_escaped} : domain_${domain_escaped} {
meta:
  description = "New files contacting ${domain}"
  target_entity = "file"
condition:
  for any lookup in vt.behaviour.dns_lookups : (
    lookup.hostname iequals "${domain}"
  )
}

rule network_watch_${domain_escaped} : domain_${domain_escaped} {
meta:
  description = "New files downloaded from ${domain}"
  target_entity = "file"
condition:
  vt.metadata.new_file and
  (vt.metadata.itw.domain.root == "${domain}" or
   vt.metadata.itw.domain.raw iendswith ".${domain}"
  )
}


rule network_watch_contact_${domain_escaped} : domain_${domain_escaped} {
meta:
  description = "New files contacting ${domain}"
  target_entity = "file"
condition:
  for any lookup in vt.behaviour.dns_lookups : (
    (lookup.hostname == "${domain}" or
     lookup.hostname iendswith ".${domain}"
    )
  )
}

rule network_watch_email_embeds_${domain_escaped} : ${domain_escaped} {
meta:
  description = "New files containing ${domain}"
  target_entity = "file"
strings:
  $domain = "${domain}"
condition:
  any of them and
  vt.metadata.new_file and
  (vt.metadata.file_type == vt.FileType.EMAIL or
   vt.metadata.file_type == vt.FileType.OUTLOOK
  )
}

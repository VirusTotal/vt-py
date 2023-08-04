rule network_watch_${domain_escaped} : ${domain_escaped} {
meta:
  description = "New files downloaded from domain ${domain}"
  target_entity = "file"
condition:
  vt.metadata.new_file and
  vt.metadata.itw.domain.raw iendswith "${domain}"
}

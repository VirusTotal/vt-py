rule network_watch_${domain_escaped} : ${domain_escaped} {
meta:
  description = "Monitor new domains for ${domain}"
  target_entity = "domain"
condition:
  vt.net.domain.new_domain and
  vt.net.domain.raw endswith "${domain}"
}

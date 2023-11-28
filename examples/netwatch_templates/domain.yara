rule network_watch_${domain_escaped} : domain_${domain_escaped} {
meta:
  description = "Monitor new subdomains for ${domain}"
  target_entity = "domain"
condition:
  vt.net.domain.new_domain and
  vt.net.domain.root == "${domain}"
}

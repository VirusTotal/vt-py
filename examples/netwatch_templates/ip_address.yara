rule network_watch_${domain_escaped} : ${domain_escaped} {
meta:
  description = "New IP addresses resolving domain ${domain} or its subdomains"
  target_entity = "ip_address"
condition:
  vt.net.ip.reverse_lookup == "${domain}"
  vt.net.ip.reverse_lookup endswith ".${domain}"
}

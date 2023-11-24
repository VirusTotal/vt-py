rule network_watch_${domain_escaped} : domain_${domain_escaped} {
meta:
  description = "Monitor new URLs in ${domain}"
  target_entity = "url"
condition:
  vt.net.url.new_url and
  vt.net.domain.root == "${domain}"
}

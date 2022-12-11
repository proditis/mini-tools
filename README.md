# mini-tools
A collection of mini tools for various purposes

* `certnames`: gets the alternate subject DNS names from a PEM certificate and performs a DNS lookup on them
* `sniprobe`: Takes a host and optional https port and after it resolves the
  hostname, grabs the DNS names of its certificate and performs GET requests,
  pinned on the first hosts' IP and thus keeping SNI happy
* `cspparse`: Parse the CSP policy from the returned headers of a given URI and
  try to extract URL and fully qualified domain names (that optionally match a given word)
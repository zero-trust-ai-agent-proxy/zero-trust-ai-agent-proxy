package zero_trust_ai_agent_proxy.authz

default allow := false

allow if {
  input.tool == "http.get"
  startswith(input.args.url, "https://api.acme.test/")
}

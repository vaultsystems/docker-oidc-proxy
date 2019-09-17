local opts = {
    redirect_uri_path = os.getenv("OID_REDIRECT_PATH") or "/redirect_uri",
    discovery = os.getenv("OID_DISCOVERY"),
    client_id = os.getenv("OID_CLIENT_ID"),
    client_secret = os.getenv("OID_CLIENT_SECRET"),
    token_endpoint_auth_method = os.getenv("OIDC_AUTH_METHOD") or "client_secret_basic",
    renew_access_token_on_expiry = os.getenv("OIDC_RENEW_ACCESS_TOKEN_ON_EXPIERY") ~= "false",
    scope = os.getenv("OIDC_AUTH_SCOPE") or "openid",
    iat_slack = 600,
}

-- call authenticate for OpenID Connect user authentication
local res, err, _target, session = require("resty.openidc").authenticate(opts)

ngx.log(ngx.INFO, tostring(res))
ngx.log(ngx.INFO, tostring(err))

ngx.log(ngx.INFO,
  "session.present=", session.present,
  ", session.data.id_token=", session.data.id_token ~= nil,
  ", session.data.authenticated=", session.data.authenticated,
  ", opts.force_reauthorize=", opts.force_reauthorize,
  ", opts.renew_access_token_on_expiry=", opts.renew_access_token_on_expiry,
  ", try_to_renew=", try_to_renew,
  ", token_expired=", token_expired
)

if err then
    ngx.status = 500
    ngx.header.content_type = 'text/html';

    ngx.say("There was an error while logging in: " .. err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

if os.getenv("REQUIRE_GROUP")~="" then
  in_group = false
  for g in res.user.groups:gmatch("([^;]*)") do
    if g==os.getenv("REQUIRE_GROUP") then in_group=true end
  end
  if in_group==false then ngx.exit(ngx.HTTP_FORBIDDEN) end
end

ngx.log(ngx.INFO, "Authentication successful, setting Auth header...")
ngx.req.set_header("Authorization", "Bearer "..session.data.enc_id_token)

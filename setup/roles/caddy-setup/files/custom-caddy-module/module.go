package happy_eyeballs_webtester_module

import (
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(&Layer4ThrottleVarHandler{})
}

package limiter

type GlobalDeviceLimitConfig struct {
	Enable        bool   `mapstructure:"Enable"`
	RedisNetwork  string `mapstructure:"RedisNetwork"` // tcp or unix
	RedisAddr     string `mapstructure:"RedisAddr"`    // host:port, or /path/to/unix.sock
	RedisUsername string `mapstructure:"RedisUsername"`
	RedisPassword string `mapstructure:"RedisPassword"`
	RedisDB       int    `mapstructure:"RedisDB"`
	Timeout       int    `mapstructure:"Timeout"`
	Expiry        int    `mapstructure:"Expiry"` // second

	// Mode "cache" (default) reuses a live same-UID/IP holder without a Redis
	// round trip; "strict" verifies every Acquire against Redis.
	Mode string `mapstructure:"Mode"`
	// FailMode "open" (default) keeps local admission on Redis failures;
	// "closed" rejects all new connections while Redis cannot be verified.
	FailMode string `mapstructure:"FailMode"`
	// Namespace overrides the derived shared key space. It is hashed and is
	// never used verbatim, so it cannot leak panel identity or credentials.
	Namespace string `mapstructure:"Namespace"`
	// IPv6Prefix masks IPv6 sources into a shared prefix; nil means /64 and an
	// explicit 0 means the full /128 address.
	IPv6Prefix *int `mapstructure:"IPv6Prefix"`
	// StrictClientIPSource acknowledges header-derived source identity in
	// strict mode: "peer" (direct transport address) or "forwarded".
	StrictClientIPSource string `mapstructure:"StrictClientIPSource"`

	// PanelType and APIHost are internal wiring hints filled by the runtime;
	// they derive the stable namespace when Namespace is empty.
	PanelType string `mapstructure:"-"`
	APIHost   string `mapstructure:"-"`
	// RuntimeOwner identifies the in-process runtime that owns this config so
	// node-tag replacement can reuse one admission manager and keep existing
	// lease renewal alive. It is never part of any Redis key.
	RuntimeOwner string `mapstructure:"-"`
}

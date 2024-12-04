package msgs

const (
	WsErr = "WsError"

	SignStarted = "Sign.Started"

	SessionJoin   = "Session.join"
	SessionStart  = "Session.start"
	SessionMsg    = "Session.message"
	SessionFinish = "Session.finish"
	SessionErr    = "Session.err"

	NodeOnline      = "Node.online"
	NodeOffline     = "Node.offline"
	SessionCreated  = "Session.created"
	SessionJoined   = "Session.joined"
	SessionFinished = "Session.finished"
)

const (
	SessionKindEcdsaKeygen = "ecdsa.keygen"
	SessionKindEcdsaAux    = "ecdsa.aux"
	SessionKindEcdsaSign   = "ecdsa.sign"
	SessionKindEddsaKeygen = "eddsa.keygen"
	SessionKindEddsaSign   = "eddsa.sign"
)

package secrets

// actorKind is who an Actor is.
type actorKind int

const (
	actorNone actorKind = iota
	actorOperator
	actorDeploy
	actorCheck
)

// Actor is the identity the endpoint or job passes to the Service, which
// authorizes it (SEC-AUTHZ). The zero Actor is refused on every operation.
type Actor struct {
	kind actorKind
	// user is the operator's user ID.
	user string
	// app and node are the deploy job's app and the node it delivers to.
	app, node string
}

// OperatorActor is a user the endpoint's session authenticated. An empty
// userID gives the zero Actor, which every operation refuses.
func OperatorActor(userID string) Actor {
	if userID == "" {
		return Actor{}
	}
	return Actor{kind: actorOperator, user: userID}
}

// DeployActor is a deploy job resolving app appID's secrets for node, the
// node it delivers to.
func DeployActor(appID, node string) Actor {
	return Actor{kind: actorDeploy, app: appID, node: node}
}

// CheckActor is the store reference check (geekdojo/geekdojo-brain#800),
// which only asks whether an app secret exists and never reads one.
func CheckActor() Actor {
	return Actor{kind: actorCheck}
}

// kindName is the actor kind as its log records name it.
func (a Actor) kindName() string {
	switch a.kind {
	case actorOperator:
		return "operator"
	case actorDeploy:
		return "deploy"
	case actorCheck:
		return "check"
	}
	return "none"
}

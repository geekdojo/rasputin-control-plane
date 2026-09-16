package bus

// Client-connection controls on the embedded server, kept out of server.go so
// the broker's startup path stays untouched.
//
// busauth uses ClientOpen and DisconnectClient to cut a revoked node's live
// session (certificates.md §4.2(1)): it records the server-assigned connection
// id the auth callout reports for every token it accepts, and closes exactly
// those ids when the token is revoked. See busauth.Store.Revoke.

// ClientOpen reports whether the client connection with this server-assigned
// id is still registered with the server. A connection is registered from the
// moment it is accepted — before its CONNECT is authenticated — until it
// closes, and ids are never reused within a server's lifetime.
func (s *Server) ClientOpen(cid uint64) bool {
	return s.ns.GetClient(cid) != nil
}

// DisconnectClient closes the client connection with this id and reports
// whether one was open to close. It works on a connection still inside its
// auth callout too: the server refuses to register a user on a closed
// connection, so a kicked in-flight authentication fails instead of landing.
func (s *Server) DisconnectClient(cid uint64) bool {
	return s.ns.DisconnectClientByID(cid) == nil
}

package bus

// Client-connection controls on the embedded server, kept out of server.go so
// the broker's startup path stays untouched.
//
// busauth uses ClientOpen and DisconnectClient to cut a revoked node's live
// session (certificates.md §4.2(1)): it records the server id and the
// server-assigned connection id the auth callout reports for every token it
// accepts, and closes exactly those connections when the token is revoked.
// See busauth.Store.Revoke.
//
// A connection is named by BOTH ids. Connection ids are never reused within
// one server's lifetime, but SetAllowNonTLS replaces the server inside the
// running process, and the new server numbers its connections from the start
// again. An id recorded on the old server must never close a connection on the
// new one, so both calls answer false for any server id but the running one's.

// ClientOpen reports whether the client connection with this id, on the
// server with this id, is still registered with the running server. A
// connection is registered from the moment it is accepted — before its
// CONNECT is authenticated — until it closes.
func (s *Server) ClientOpen(serverID string, cid uint64) bool {
	ns := s.current()
	return ns != nil && ns.ID() == serverID && ns.GetClient(cid) != nil
}

// DisconnectClient closes the client connection with this id on the server
// with this id, and reports whether one was open to close. It works on a
// connection still inside its auth callout too: the server refuses to
// register a user on a closed connection, so a kicked in-flight
// authentication fails instead of landing. A server id that is not the
// running server's closes nothing: that server, and every connection on it, is
// already gone.
func (s *Server) DisconnectClient(serverID string, cid uint64) bool {
	ns := s.current()
	return ns != nil && ns.ID() == serverID && ns.DisconnectClientByID(cid) == nil
}

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package test

import (
	"bytes"
	"testing"

	"github.com/weatheringocean/crypto/ssh"
	"github.com/weatheringocean/crypto/ssh/agent"
)

func TestAgentForward(t *testing.T) {
	server := newServer(t)
	conn := server.Dial(clientConfig())
	defer conn.Close()

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: testPrivateKeys["ecdsa"]}); err != nil {
		t.Fatalf("Error adding key: %s", err)
	}
	if err := keyring.Add(agent.AddedKey{
		PrivateKey:       testPrivateKeys["ecdsa"],
		ConfirmBeforeUse: true,
		LifetimeSecs:     3600,
	}); err != nil {
		t.Fatalf("Error adding key with constraints: %s", err)
	}
	pub := testPublicKeys["ecdsa"]

	sess, err := conn.NewSession()
	if err != nil {
		skipIfIssue64959(t, err)
		t.Fatalf("NewSession: %v", err)
	}
	if err := agent.RequestAgentForwarding(sess); err != nil {
		t.Fatalf("RequestAgentForwarding: %v", err)
	}

	if err := agent.ForwardToAgent(conn, keyring); err != nil {
		t.Fatalf("SetupForwardKeyring: %v", err)
	}
	out, err := sess.CombinedOutput("ssh-add -L")
	if err != nil {
		t.Fatalf("running ssh-add: %v, out %s", err, out)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(out)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(%q): %v", out, err)
	}

	if !bytes.Equal(key.Marshal(), pub.Marshal()) {
		t.Fatalf("got key %s, want %s", ssh.MarshalAuthorizedKey(key), ssh.MarshalAuthorizedKey(pub))
	}
}

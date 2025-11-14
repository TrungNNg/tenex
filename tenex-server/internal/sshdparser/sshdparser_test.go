package sshdparser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseLine(t *testing.T) {
	parser := New()

	t.Run("DNS warning message", func(t *testing.T) {
		message := "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 6, 55, 46, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24200", entry.PID)
		assert.Equal(t, DNSWarning, entry.EventType)
		assert.Equal(t, "173.234.31.186", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Invalid user message", func(t *testing.T) {
		message := "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 6, 55, 46, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24200", entry.PID)
		assert.Equal(t, InvalidUser, entry.EventType)
		assert.Equal(t, "173.234.31.186", entry.SourceIP)
		assert.Equal(t, "webmaster", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Auth request message", func(t *testing.T) {
		message := "Dec 10 06:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 6, 55, 46, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24200", entry.PID)
		assert.Equal(t, AuthRequest, entry.EventType)
		assert.Equal(t, "", entry.SourceIP)
		assert.Equal(t, "webmaster", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("PAM message", func(t *testing.T) {
		message := "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 6, 55, 46, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24200", entry.PID)
		assert.Equal(t, PAMMessage, entry.EventType)
		assert.Equal(t, "173.234.31.186", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Failed password for invalid user", func(t *testing.T) {
		message := "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 6, 55, 48, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24200", entry.PID)
		assert.Equal(t, AuthFailure, entry.EventType)
		assert.Equal(t, "173.234.31.186", entry.SourceIP)
		assert.Equal(t, "webmaster", entry.Username)
		assert.Equal(t, "38926", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Failed password for valid user", func(t *testing.T) {
		message := "Dec 10 07:13:56 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 7, 13, 56, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24227", entry.PID)
		assert.Equal(t, AuthFailure, entry.EventType)
		assert.Equal(t, "5.36.59.76", entry.SourceIP)
		assert.Equal(t, "root", entry.Username)
		assert.Equal(t, "42393", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Failed none message", func(t *testing.T) {
		message := "Dec 10 08:24:58 LabSZ sshd[24367]: Failed none for invalid user admin from 5.188.10.180 port 52631 ssh2"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 8, 24, 58, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24367", entry.PID)
		assert.Equal(t, AuthFailure, entry.EventType)
		assert.Equal(t, "5.188.10.180", entry.SourceIP)
		assert.Equal(t, "admin", entry.Username)
		assert.Equal(t, "52631", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Accepted password message", func(t *testing.T) {
		message := "Dec 10 08:30:00 LabSZ sshd[25000]: Accepted password for john from 192.168.1.100 port 55000 ssh2"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 8, 30, 0, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "25000", entry.PID)
		assert.Equal(t, AuthSuccess, entry.EventType)
		assert.Equal(t, "192.168.1.100", entry.SourceIP)
		assert.Equal(t, "john", entry.Username)
		assert.Equal(t, "55000", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Accepted publickey message", func(t *testing.T) {
		message := "Dec 10 08:30:00 LabSZ sshd[25001]: Accepted publickey for alice from 10.0.0.1 port 60000 ssh2"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 8, 30, 0, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "25001", entry.PID)
		assert.Equal(t, AuthSuccess, entry.EventType)
		assert.Equal(t, "10.0.0.1", entry.SourceIP)
		assert.Equal(t, "alice", entry.Username)
		assert.Equal(t, "60000", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Connection closed message", func(t *testing.T) {
		message := "Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 6, 55, 48, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24200", entry.PID)
		assert.Equal(t, ConnectionClosed, entry.EventType)
		assert.Equal(t, "173.234.31.186", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Received disconnect message", func(t *testing.T) {
		message := "Dec 10 07:07:45 LabSZ sshd[24206]: Received disconnect from 52.80.34.196: 11: Bye Bye [preauth]"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 7, 7, 45, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24206", entry.PID)
		assert.Equal(t, Disconnect, entry.EventType)
		assert.Equal(t, "52.80.34.196", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Message repeated message", func(t *testing.T) {
		message := "Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 7, 13, 56, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24227", entry.PID)
		assert.Equal(t, RepeatedMessage, entry.EventType)
		assert.Equal(t, "", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Too many auth failure message", func(t *testing.T) {
		message := "Dec 10 07:13:56 LabSZ sshd[24227]: Disconnecting: Too many authentication failures for root [preauth]"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 7, 13, 56, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24227", entry.PID)
		assert.Equal(t, MaxAuthFailures, entry.EventType)
		assert.Equal(t, "", entry.SourceIP)
		assert.Equal(t, "root", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("No identification string message", func(t *testing.T) {
		message := "Dec 10 07:34:33 LabSZ sshd[24301]: Did not receive identification string from 123.235.32.19"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 7, 34, 33, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24301", entry.PID)
		assert.Equal(t, NoIdentification, entry.EventType)
		assert.Equal(t, "123.235.32.19", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Error message", func(t *testing.T) {
		message := "Dec 10 07:51:15 LabSZ sshd[24324]: error: Received disconnect from 195.154.37.122: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]"
		entry, recognized := parser.ParseLine(message)
		assert.True(t, recognized)

		expectedTime := time.Date(0, time.December, 10, 7, 51, 15, 0, time.UTC)
		assert.Equal(t, expectedTime, entry.Timestamp)
		assert.Equal(t, "LabSZ", entry.Hostname)
		assert.Equal(t, "24324", entry.PID)
		assert.Equal(t, ErrorMessage, entry.EventType)
		assert.Equal(t, "195.154.37.122", entry.SourceIP)
		assert.Equal(t, "", entry.Username)
		assert.Equal(t, "", entry.Port)
		assert.Equal(t, message, entry.RawMessage)
	})

	t.Run("Unrecognized message", func(t *testing.T) {
		message := "Dec 10 08:00:00 LabSZ sshd[30000]: Some unknown message format"
		_, recognized := parser.ParseLine(message)
		assert.False(t, recognized)
	})
}

func TestParseFile(t *testing.T) {
	parser := New()

	testContent := []byte(`Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]
Dec 10 07:07:45 LabSZ kernel[1234]: Some kernel message
Dec 10 07:13:56 LabSZ sshd[24227]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]
Dec 10 08:00:00 LabSZ sshd[30000]: Some unknown sshd message

Dec 10 08:30:00 LabSZ sshd[25000]: Accepted password for john from 192.168.1.100 port 55000 ssh2`)

	parsed, unparsed := parser.ParseFile(testContent)

	// Should parse 5 recognized sshd lines
	assert.Equal(t, 5, len(parsed))

	// Should have 1 unrecognized sshd line
	assert.Equal(t, 1, len(unparsed))

	// Verify first entry
	if len(parsed) > 0 {
		res := parsed[0]
		assert.Equal(t, InvalidUser, res.EventType)
		assert.Equal(t, "173.234.31.186", res.SourceIP)
		assert.Equal(t, "webmaster", res.Username)
	}

	// Verify last entry
	if len(parsed) > 0 {
		res := parsed[len(parsed)-1]
		assert.Equal(t, AuthSuccess, res.EventType)
		assert.Equal(t, "john", res.Username)
	}

	// Test empty content
	emptyParsed, emptyUnparsed := parser.ParseFile([]byte(""))
	assert.Empty(t, emptyParsed)
	assert.Empty(t, emptyUnparsed)
}

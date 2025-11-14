package sshdparser

import (
	"regexp"
	"strings"
	"time"
)

// SSH message types
const (
	DNSWarning       = "dns_warning"
	InvalidUser      = "invalid_user"
	AuthRequest      = "auth_request"
	PAMMessage       = "pam_message"
	AuthFailure      = "auth_failure"
	AuthSuccess      = "auth_success"
	ConnectionClosed = "connection_closed"
	Disconnect       = "disconnect"
	RepeatedMessage  = "repeated_message"
	MaxAuthFailures  = "max_auth_failures"
	NoIdentification = "no_identification"
	ErrorMessage     = "error"
)

type LogEntry struct {
	Timestamp  time.Time
	Hostname   string
	PID        string
	EventType  string
	SourceIP   string
	Username   string
	Port       string
	RawMessage string
}

type SSHDParser struct {
	timestampRe *regexp.Regexp
	pidRe       *regexp.Regexp
	ipRe        *regexp.Regexp
	portRe      *regexp.Regexp
}

func New() *SSHDParser {
	return &SSHDParser{
		timestampRe: regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`),
		pidRe:       regexp.MustCompile(`sshd\[(\d+)\]`),
		ipRe:        regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
		portRe:      regexp.MustCompile(`port (\d+)`),
	}
}

func (p *SSHDParser) ParseLine(line string) (*LogEntry, bool) {
	entry := &LogEntry{RawMessage: line}

	// Timestamp
	if match := p.timestampRe.FindStringSubmatch(line); match != nil {
		ts, err := time.Parse("Jan 2 15:04:05", match[1])
		if err == nil {
			entry.Timestamp = ts
		}
	}

	// Host
	parts := strings.Fields(line)
	if len(parts) >= 4 {
		entry.Hostname = parts[3]
	}

	// PID
	if match := p.pidRe.FindStringSubmatch(line); match != nil {
		entry.PID = match[1]
	}

	// Message
	msgStart := strings.Index(line, "]: ")
	if msgStart == -1 {
		return entry, false
	}
	message := line[msgStart+3:]

	recognized := p.classifyMessage(entry, message)

	return entry, recognized
}

func (p *SSHDParser) classifyMessage(entry *LogEntry, message string) bool {
	messageLower := strings.ToLower(message)

	if strings.Contains(message, "message repeated") {
		entry.EventType = RepeatedMessage
		return true
	}

	if strings.HasPrefix(messageLower, "error:") {
		entry.EventType = ErrorMessage
		if ip := p.ipRe.FindString(message); ip != "" {
			entry.SourceIP = ip
		}
		return true
	}

	if strings.Contains(message, "POSSIBLE BREAK-IN ATTEMPT") ||
		strings.Contains(message, "reverse mapping checking") {
		entry.EventType = DNSWarning
		if ip := p.ipRe.FindString(message); ip != "" {
			entry.SourceIP = ip
		}
		return true
	}

	if strings.Contains(message, "Invalid user") {
		entry.EventType = InvalidUser
		parts := strings.Fields(message)
		for i, part := range parts {
			if part == "user" && i+1 < len(parts) {
				entry.Username = parts[i+1]
			}
			if part == "from" && i+1 < len(parts) {
				entry.SourceIP = parts[i+1]
			}
		}
		return true
	}

	if strings.Contains(message, "input_userauth_request") {
		entry.EventType = AuthRequest
		if strings.Contains(message, "invalid user") {
			parts := strings.Fields(message)
			for i, part := range parts {
				if part == "user" && i+1 < len(parts) {
					entry.Username = parts[i+1]
					break
				}
			}
		}
		return true
	}

	if strings.Contains(message, "pam_unix") || strings.HasPrefix(message, "PAM") {
		entry.EventType = PAMMessage
		if ip := p.ipRe.FindString(message); ip != "" {
			entry.SourceIP = ip
		}
		if idx := strings.Index(message, " user="); idx != -1 {
			userPart := message[idx+6:]
			username := strings.Fields(userPart)[0]
			entry.Username = strings.TrimRight(username, " ")
		}
		return true
	}

	if strings.Contains(message, "Failed password") || strings.Contains(message, "Failed none") {
		entry.EventType = AuthFailure
		parts := strings.Fields(message)
		for i, part := range parts {
			if part == "for" && i+1 < len(parts) {
				if parts[i+1] == "invalid" && i+3 < len(parts) {
					entry.Username = parts[i+3]
				} else {
					entry.Username = parts[i+1]
				}
			}
			if part == "from" && i+1 < len(parts) {
				entry.SourceIP = parts[i+1]
			}
		}
		if match := p.portRe.FindStringSubmatch(message); match != nil {
			entry.Port = match[1]
		}
		return true
	}

	if strings.Contains(message, "Accepted password") || strings.Contains(message, "Accepted publickey") {
		entry.EventType = AuthSuccess
		parts := strings.Fields(message)
		for i, part := range parts {
			if part == "for" && i+1 < len(parts) {
				entry.Username = parts[i+1]
			}
			if part == "from" && i+1 < len(parts) {
				entry.SourceIP = parts[i+1]
			}
		}
		if match := p.portRe.FindStringSubmatch(message); match != nil {
			entry.Port = match[1]
		}
		return true
	}

	if strings.Contains(message, "Connection closed") {
		entry.EventType = ConnectionClosed
		if ip := p.ipRe.FindString(message); ip != "" {
			entry.SourceIP = ip
		}
		return true
	}

	if strings.Contains(message, "Received disconnect") {
		entry.EventType = Disconnect
		if ip := p.ipRe.FindString(message); ip != "" {
			entry.SourceIP = ip
		}
		return true
	}

	if strings.Contains(messageLower, "too many authentication failures") {
		entry.EventType = MaxAuthFailures
		parts := strings.Fields(message)
		for i, part := range parts {
			if part == "for" && i+1 < len(parts) {
				entry.Username = parts[i+1]
			}
		}
		return true
	}

	if strings.Contains(message, "Did not receive identification string") {
		entry.EventType = NoIdentification
		if ip := p.ipRe.FindString(message); ip != "" {
			entry.SourceIP = ip
		}
		return true
	}

	// Unrecognized pattern
	return false
}

func (p *SSHDParser) ParseFile(content []byte) (parsed []*LogEntry, unparsed []string) {
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if !strings.Contains(line, "sshd") {
			continue
		}

		entry, recognized := p.ParseLine(line)
		if recognized {
			parsed = append(parsed, entry)
		} else {
			unparsed = append(unparsed, line)
		}
	}

	return parsed, unparsed
}

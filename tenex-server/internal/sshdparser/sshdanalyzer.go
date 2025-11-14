package sshdparser

import (
	"slices"
	"time"
)

type Analysis struct {
	TotalEvents int

	DNSWarningCount       int
	InvalidUserCount      int
	AuthRequestCount      int
	PAMMessageCount       int
	AuthFailuresCount     int
	AuthSuccessCount      int
	ConnectionClosedCount int
	DisconnectCount       int
	RepeatedMessageCount  int
	MaxAuthFailuresCount  int
	NoIdentificationCount int
	ErrorMessageCount     int

	UniqueIPs int
	TimeRange string

	Anomalies []*Anomaly
}

// Anomaly keep track of IP address associate with suspicious message types.
// Such messages types are:
// DNSWarning, InvalidUser, AuthFailure, RepeatedMessage, MaxAuthFailures, NoIdentification.
// It also keep track of PIDs associate with this IP address, which can later be used for
// further analysis.
type Anomaly struct {
	IP   string
	PIDs []string

	DNSWarningsCount      int
	InvalidUserCount      int
	AuthFailuresCount     int
	RepeatedMessageCount  int
	MaxAuthFailuresCount  int
	NoIdentificationCount int

	FirstSeen time.Time
	LastSeen  time.Time
	Usernames []string
}

func Analyze(entries []*LogEntry) *Analysis {
	a := &Analysis{}
	uniqueIPs := make(map[string]bool)

	anomalies := make(map[string]*Anomaly)

	for _, e := range entries {
		a.TotalEvents++

		switch e.EventType {
		case DNSWarning:
			a.DNSWarningCount += 1
		case InvalidUser:
			a.InvalidUserCount += 1
		case AuthRequest:
			a.AuthRequestCount += 1
		case PAMMessage:
			a.PAMMessageCount += 1
		case AuthFailure:
			a.AuthFailuresCount += 1
		case AuthSuccess:
			a.AuthSuccessCount += 1
		case ConnectionClosed:
			a.ConnectionClosedCount += 1
		case Disconnect:
			a.DisconnectCount += 1
		case RepeatedMessage:
			a.RepeatedMessageCount += 1
		case MaxAuthFailures:
			a.MaxAuthFailuresCount += 1
		case NoIdentification:
			a.NoIdentificationCount += 1
		case ErrorMessage:
			a.ErrorMessageCount += 1
		}
		if e.SourceIP != "" {
			uniqueIPs[e.SourceIP] = true
		}

		if isSuspicious(e.EventType) {
			if anomalies[e.SourceIP] == nil {
				anomalies[e.SourceIP] = &Anomaly{
					IP:        e.SourceIP,
					PIDs:      []string{},
					Usernames: []string{},
					FirstSeen: e.Timestamp,
				}
			}

			anomaly := anomalies[e.SourceIP]
			anomaly.LastSeen = e.Timestamp

			if !slices.Contains(anomaly.PIDs, e.PID) {
				anomaly.PIDs = append(anomaly.PIDs, e.PID)
			}

			if !slices.Contains(anomaly.Usernames, e.Username) {
				anomaly.Usernames = append(anomaly.Usernames, e.Username)
			}

			switch e.EventType {
			case DNSWarning:
				anomaly.DNSWarningsCount++
			case InvalidUser:
				anomaly.InvalidUserCount++
			case AuthFailure:
				anomaly.AuthFailuresCount++
			case RepeatedMessage:
				anomaly.RepeatedMessageCount++
			case MaxAuthFailures:
				anomaly.MaxAuthFailuresCount++
				ip := findIPByPID(entries, e.PID)
				if ip != "" {
					if anomalies[ip] == nil {
						anomalies[ip] = &Anomaly{
							IP:        ip,
							PIDs:      []string{},
							Usernames: []string{},
							FirstSeen: e.Timestamp,
						}
					}
					anomalies[ip].MaxAuthFailuresCount++
					if slices.Contains(anomalies[ip].PIDs, e.PID) {
						anomalies[ip].PIDs = append(anomalies[ip].PIDs, e.PID)
					}
				}
			case NoIdentification:
				anomaly.NoIdentificationCount++
			}
		}
	}

	a.UniqueIPs = len(uniqueIPs)

	if len(entries) > 0 {
		a.TimeRange = entries[0].Timestamp.Format("Jan 2 15:04") + " - " +
			entries[len(entries)-1].Timestamp.Format("Jan 2 15:04")
	}

	for _, anomaly := range anomalies {
		a.Anomalies = append(a.Anomalies, anomaly)
	}

	return a
}

func isSuspicious(eventType string) bool {
	switch eventType {
	case DNSWarning, InvalidUser, AuthFailure, RepeatedMessage, MaxAuthFailures, NoIdentification:
		return true
	}
	return false
}

func findIPByPID(entries []*LogEntry, pid string) string {
	for _, e := range entries {
		if e.PID == pid && e.SourceIP != "" {
			return e.SourceIP
		}
	}
	return ""
}

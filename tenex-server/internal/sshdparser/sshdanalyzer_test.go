package sshdparser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

/*
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

*/

func TestAnalyze(t *testing.T) {

	baseTime := time.Date(2024, 12, 10, 6, 55, 0, 0, time.UTC)

	t.Run("DNSWarning entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: DNSWarning,
				SourceIP:  "1.2.3.4",
				Username:  "",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.DNSWarningCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		assert.NotEmpty(t, res.Anomalies)
		assert.Equal(t, "1.2.3.4", res.Anomalies[0].IP)
		assert.NotEmpty(t, res.Anomalies[0].PIDs)
		assert.Equal(t, "12345", res.Anomalies[0].PIDs[0])
		assert.Equal(t, 1, res.Anomalies[0].DNSWarningsCount)

		assert.Equal(t, baseTime, res.Anomalies[0].FirstSeen)
		assert.Equal(t, baseTime, res.Anomalies[0].LastSeen)
	})

	t.Run("InvalidUser entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: InvalidUser,
				SourceIP:  "1.2.3.4",
				Username:  "webmaster",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.InvalidUserCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		assert.NotEmpty(t, res.Anomalies)
		assert.Equal(t, "1.2.3.4", res.Anomalies[0].IP)
		assert.NotEmpty(t, res.Anomalies[0].PIDs)
		assert.Equal(t, "12345", res.Anomalies[0].PIDs[0])
		assert.Equal(t, 1, res.Anomalies[0].InvalidUserCount)
		assert.Equal(t, baseTime, res.Anomalies[0].FirstSeen)
		assert.Equal(t, baseTime, res.Anomalies[0].LastSeen)
	})

	t.Run("AuthRequest entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: AuthRequest,
				SourceIP:  "1.2.3.4",
				Username:  "admin",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.AuthRequestCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		// AuthRequest is not suspicious, no anomalies
		assert.Empty(t, res.Anomalies)
	})

	t.Run("PAMMessage entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: PAMMessage,
				SourceIP:  "1.2.3.4",
				Username:  "",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.PAMMessageCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		// PAMMessage is not suspicious, no anomalies
		assert.Empty(t, res.Anomalies)
	})

	t.Run("AuthFailure entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: AuthFailure,
				SourceIP:  "1.2.3.4",
				Username:  "root",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.AuthFailuresCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		assert.NotEmpty(t, res.Anomalies)
		assert.Equal(t, "1.2.3.4", res.Anomalies[0].IP)
		assert.NotEmpty(t, res.Anomalies[0].PIDs)
		assert.Equal(t, "12345", res.Anomalies[0].PIDs[0])
		assert.Equal(t, 1, res.Anomalies[0].AuthFailuresCount)
		assert.Equal(t, baseTime, res.Anomalies[0].FirstSeen)
		assert.Equal(t, baseTime, res.Anomalies[0].LastSeen)
	})

	t.Run("AuthSuccess entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: AuthSuccess,
				SourceIP:  "192.168.1.100",
				Username:  "john",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.AuthSuccessCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		// AuthSuccess is not suspicious, no anomalies
		assert.Empty(t, res.Anomalies)
	})

	t.Run("ConnectionClosed entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: ConnectionClosed,
				SourceIP:  "1.2.3.4",
				Username:  "",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.ConnectionClosedCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		// ConnectionClosed is not suspicious, no anomalies
		assert.Empty(t, res.Anomalies)
	})

	t.Run("Disconnect entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: Disconnect,
				SourceIP:  "1.2.3.4",
				Username:  "",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.DisconnectCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		// Disconnect is not suspicious, no anomalies
		assert.Empty(t, res.Anomalies)
	})

	t.Run("RepeatedMessage entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: RepeatedMessage,
				SourceIP:  "1.2.3.4",
				Username:  "root",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.RepeatedMessageCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		assert.NotEmpty(t, res.Anomalies)
		assert.Equal(t, "1.2.3.4", res.Anomalies[0].IP)
		assert.NotEmpty(t, res.Anomalies[0].PIDs)
		assert.Equal(t, "12345", res.Anomalies[0].PIDs[0])
		assert.Equal(t, 1, res.Anomalies[0].RepeatedMessageCount)
		assert.Equal(t, baseTime, res.Anomalies[0].FirstSeen)
		assert.Equal(t, baseTime, res.Anomalies[0].LastSeen)
	})

	t.Run("MaxAuthFailures entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: AuthFailure,
				SourceIP:  "1.2.3.4",
				Username:  "root",
				PID:       "12345",
				Timestamp: baseTime,
			},
			{
				EventType: MaxAuthFailures,
				SourceIP:  "",
				Username:  "root",
				PID:       "12345",
				Timestamp: baseTime.Add(5 * time.Second),
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 2, res.TotalEvents)
		assert.Equal(t, 1, res.MaxAuthFailuresCount)
		assert.Equal(t, 1, res.UniqueIPs)

		assert.NotEmpty(t, res.Anomalies)
		assert.Equal(t, "1.2.3.4", res.Anomalies[0].IP)
		assert.Equal(t, 1, res.Anomalies[0].MaxAuthFailuresCount)
	})

	t.Run("NoIdentification entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: NoIdentification,
				SourceIP:  "1.2.3.4",
				Username:  "",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.NoIdentificationCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		assert.NotEmpty(t, res.Anomalies)
		assert.Equal(t, "1.2.3.4", res.Anomalies[0].IP)
		assert.NotEmpty(t, res.Anomalies[0].PIDs)
		assert.Equal(t, "12345", res.Anomalies[0].PIDs[0])
		assert.Equal(t, 1, res.Anomalies[0].NoIdentificationCount)
		assert.Equal(t, baseTime, res.Anomalies[0].FirstSeen)
		assert.Equal(t, baseTime, res.Anomalies[0].LastSeen)
	})

	t.Run("ErrorMessage entry", func(t *testing.T) {
		entries := []*LogEntry{
			{
				EventType: ErrorMessage,
				SourceIP:  "1.2.3.4",
				Username:  "",
				PID:       "12345",
				Timestamp: baseTime,
			},
		}
		res := Analyze(entries)
		assert.Equal(t, 1, res.TotalEvents)
		assert.Equal(t, 1, res.ErrorMessageCount)
		assert.Equal(t, 1, res.UniqueIPs)

		expectedTimeRange := baseTime.Format("Jan 2 15:04") + " - " + baseTime.Format("Jan 2 15:04")
		assert.Equal(t, expectedTimeRange, res.TimeRange)

		// ErrorMessage is not suspicious by default, no anomalies
		assert.Empty(t, res.Anomalies)
	})

	t.Run("All event type", func(t *testing.T) {
		baseTime := time.Date(2024, 12, 10, 6, 55, 0, 0, time.UTC)
		entries := []*LogEntry{
			{EventType: DNSWarning, SourceIP: "1.2.3.4", PID: "1", Timestamp: baseTime},
			{EventType: InvalidUser, SourceIP: "1.2.3.4", PID: "2", Timestamp: baseTime},
			{EventType: AuthRequest, SourceIP: "1.2.3.4", PID: "3", Timestamp: baseTime},
			{EventType: PAMMessage, SourceIP: "1.2.3.4", PID: "4", Timestamp: baseTime},
			{EventType: AuthFailure, SourceIP: "1.2.3.4", PID: "5", Timestamp: baseTime},
			{EventType: AuthSuccess, SourceIP: "1.2.3.4", PID: "6", Timestamp: baseTime},
			{EventType: ConnectionClosed, SourceIP: "1.2.3.4", PID: "7", Timestamp: baseTime},
			{EventType: Disconnect, SourceIP: "1.2.3.4", PID: "8", Timestamp: baseTime},
			{EventType: RepeatedMessage, SourceIP: "1.2.3.4", PID: "9", Timestamp: baseTime},
			{EventType: MaxAuthFailures, PID: "5", Timestamp: baseTime},
			{EventType: NoIdentification, SourceIP: "1.2.3.4", PID: "11", Timestamp: baseTime},
			{EventType: ErrorMessage, SourceIP: "1.2.3.4", PID: "12", Timestamp: baseTime},
		}

		analysis := Analyze(entries)
		assert.Equal(t, analysis.DNSWarningCount, 1)
		assert.Equal(t, analysis.InvalidUserCount, 1)
		assert.Equal(t, analysis.AuthRequestCount, 1)
		assert.Equal(t, analysis.PAMMessageCount, 1)
		assert.Equal(t, analysis.AuthFailuresCount, 1)
		assert.Equal(t, analysis.AuthSuccessCount, 1)
		assert.Equal(t, analysis.ConnectionClosedCount, 1)
		assert.Equal(t, analysis.DisconnectCount, 1)
		assert.Equal(t, analysis.RepeatedMessageCount, 1)
		assert.Equal(t, analysis.MaxAuthFailuresCount, 1)
		assert.Equal(t, analysis.NoIdentificationCount, 1)
		assert.Equal(t, analysis.ErrorMessageCount, 1)
	})
}

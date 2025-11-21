package main

import (
	"bytes" // Added missing import
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/nash0810/kubecustos/pkg/models"
)

var (
	db *sql.DB

	// In-memory fallback stores for local development (used when DATABASE_URL is not set)
	memEvents = make([]models.EnrichedEvent, 0)
	memAlerts = make([]models.Alert, 0)
	memLock   = &sync.Mutex{}

	// Prometheus Metrics
	eventsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_events_total",
		Help: "Total number of events received by the backend.",
	})
	alertsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_alerts_total",
		Help: "Total number of alerts generated, labeled by rule and severity.",
	}, []string{"rule", "severity"})
	backendRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_backend_requests_total",
		Help: "Total number of HTTP requests to the backend API.",
	}, []string{"endpoint"})
)

func init() {
	prometheus.MustRegister(eventsProcessed, alertsTotal, backendRequestsTotal)
}

// connectDB sets up the PostgreSQL connection pool.
func connectDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Println("DATABASE_URL not set — running in-memory fallback (no Postgres). To enable Postgres set DATABASE_URL env var.")
		return
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	log.Println("Successfully connected to PostgreSQL.")
	createTables()
}

// createTables ensures the necessary tables exist.
func createTables() {
	eventsTable := `
	CREATE TABLE IF NOT EXISTS events (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
		pod_name VARCHAR(255) NOT NULL,
		namespace VARCHAR(255) NOT NULL,
		node_name VARCHAR(255) NOT NULL,
		pid INT NOT NULL,
		ppid INT NOT NULL,
		process_name VARCHAR(255) NOT NULL,
		command_line TEXT NOT NULL,
		container_id VARCHAR(64)
	);`

	alertsTable := `
	CREATE TABLE IF NOT EXISTS alerts (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
		rule_name VARCHAR(255) NOT NULL,
		severity VARCHAR(50) NOT NULL,
		pod_name VARCHAR(255) NOT NULL,
		namespace VARCHAR(255) NOT NULL,
		node_name VARCHAR(255) NOT NULL,
		full_command TEXT NOT NULL,
		event_id INT REFERENCES events(id) ON DELETE CASCADE
	);`

	if _, err := db.Exec(eventsTable); err != nil {
		log.Fatalf("Error creating events table: %v", err)
	}
	if _, err := db.Exec(alertsTable); err != nil {
		log.Fatalf("Error creating alerts table: %v", err)
	}
	log.Println("Database tables created or verified.")
}

// handleEvents is the main entry point for the collector.
func handleEvents(w http.ResponseWriter, r *http.Request) {
	backendRequestsTotal.WithLabelValues("/api/v1/events").Inc()
	var event models.EnrichedEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	eventsProcessed.Inc()
	log.Printf("Received event: %s in %s/%s", event.Comm, event.Namespace, event.PodName)

	// Phase 1: Store Event (Postgres if available, otherwise in-memory)
	var eventID int64
	if db != nil {
		err := db.QueryRow(`
			INSERT INTO events (timestamp, pod_name, namespace, node_name, pid, ppid, process_name, command_line, container_id) 
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
			RETURNING id`,
			event.Timestamp, event.PodName, event.Namespace, event.NodeName, event.PID, event.PPID, event.Comm, event.FullCommand, event.ContainerID).Scan(&eventID)
		if err != nil {
			log.Printf("Failed to store event in DB: %v", err)
			http.Error(w, "Internal server error during persistence", http.StatusInternalServerError)
			return
		}
	} else {
		// In-memory fallback
		memLock.Lock()
		eventID = int64(len(memEvents) + 1)
		memEvents = append(memEvents, event)
		memLock.Unlock()
	}

	// Phase 2: Run Rule Engine
	if alert := checkRules(event); alert.RuleName != "" {
		alert.EventID = eventID

		if db != nil {
			// Phase 3: Store Alert in Postgres
			_, err := db.Exec(`
				INSERT INTO alerts (timestamp, rule_name, severity, pod_name, namespace, node_name, full_command, event_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				alert.Timestamp, alert.RuleName, alert.Severity, alert.PodName, alert.Namespace, alert.NodeName, alert.FullCommand, alert.EventID)
			if err != nil {
				log.Printf("Failed to store alert: %v", err)
			} else {
				alertsTotal.WithLabelValues(alert.RuleName, alert.Severity).Inc()
				go sendSlackAlert(alert, event)
			}
		} else {
			// In-memory alert
			memLock.Lock()
			alert.ID = int64(len(memAlerts) + 1)
			memAlerts = append(memAlerts, alert)
			memLock.Unlock()
			alertsTotal.WithLabelValues(alert.RuleName, alert.Severity).Inc()
			go sendSlackAlert(alert, event)
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

// --- Rule Engine (Moved from Collector) ---

// checkRules evaluates the event against hardcoded rules.
func checkRules(event models.EnrichedEvent) models.Alert {
	// Rule 1: Crypto Miner
	if strings.Contains(event.FullCommand, "xmrig") || event.Comm == "xmrig" {
		return models.Alert{
			RuleName: "Crypto Miner Execution Detected",
			Severity: "CRITICAL",
			PodName: event.PodName,
			Namespace: event.Namespace,
			NodeName: event.NodeName,
			FullCommand: event.FullCommand,
			Timestamp: event.Timestamp, // FIX: Added field name
		}
	}

	// Rule 2: Suspicious Supply-chain pattern (curl | bash)
	isPipeAttack := (strings.Contains(event.FullCommand, "curl") || strings.Contains(event.FullCommand, "wget")) && 
		(strings.Contains(event.FullCommand, "bash") || strings.Contains(event.FullCommand, "sh"))
	if isPipeAttack {
		return models.Alert{
			RuleName: "Supply Chain Pipeline Attack Detected",
			Severity: "HIGH",
			PodName: event.PodName,
			Namespace: event.Namespace,
			NodeName: event.NodeName,
			FullCommand: event.FullCommand,
			Timestamp: event.Timestamp, // FIX: Added field name
		}
	}

	// Rule 3: Execution from /tmp
	if strings.HasPrefix(event.FullCommand, "/tmp/") || strings.HasPrefix(event.FullCommand, "/dev/shm/") {
		return models.Alert{
			RuleName: "Suspicious Execution from Temporary Directory",
			Severity: "MEDIUM",
			PodName: event.PodName,
			Namespace: event.Namespace,
			NodeName: event.NodeName,
			FullCommand: event.FullCommand,
			Timestamp: event.Timestamp, // FIX: Added field name
		}
	}

	return models.Alert{}
}

// --- Slack Alerting (Moved from Collector) ---

func sendSlackAlert(alert models.Alert, event models.EnrichedEvent) {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		log.Println("SLACK_WEBHOOK_URL not set, skipping alert.")
		return
	}
	
	// Construct the Slack Payload using structs from pkg/models
	// We assume the models package contains SlackField, SlackBlock, and SlackPayload
	msg := models.SlackPayload{ 
		Blocks: []models.SlackBlock{
			{
				Type: "header",
				Text: &models.SlackField{ Type: "plain_text", Text: fmt.Sprintf("🚨 Security Alert (%s): %s", alert.Severity, alert.RuleName) },
			},
			{
				Type: "section",
				Fields: []models.SlackField{
					{Type: "mrkdwn", Text: fmt.Sprintf("*Pod:*\n`%s/%s`", alert.Namespace, alert.PodName)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Node:*\n`%s`", alert.NodeName)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Process Name:*\n`%s`", event.Comm)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*PID:*\n`%d`", event.PID)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Severity:*\n`%s`", alert.Severity)},
					{Type: "mrkdwn", Text: fmt.Sprintf("*Time:*\n`%s`", alert.Timestamp.Format(time.RFC1123))},
				},
			},
			{
				Type: "section",
				Text: &models.SlackField{ Type: "mrkdwn", Text: fmt.Sprintf("*Full Command:*\n```%s```", alert.FullCommand) },
			},
		},
	}
	
	// Marshal the payload
	payload, err := json.Marshal(msg) 
	if err != nil {
		log.Printf("Failed to marshal Slack payload: %v", err)
		return
	}
	
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Failed to send Slack alert: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Slack webhook returned non-2xx status: %d", resp.StatusCode)
	}
}

// handleHealth provides a simple health check.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	backendRequestsTotal.WithLabelValues("/health").Inc()
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleGetAlerts returns recent alerts (from Postgres if configured, otherwise in-memory)
func handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	backendRequestsTotal.WithLabelValues("/api/v1/alerts").Inc()
	var out []models.Alert
	if db != nil {
		rows, err := db.Query(`SELECT id, timestamp, rule_name, severity, pod_name, namespace, node_name, full_command, event_id FROM alerts ORDER BY timestamp DESC LIMIT 100`)
		if err != nil {
			http.Error(w, "Failed to query alerts", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var a models.Alert
			if err := rows.Scan(&a.ID, &a.Timestamp, &a.RuleName, &a.Severity, &a.PodName, &a.Namespace, &a.NodeName, &a.FullCommand, &a.EventID); err != nil {
				continue
			}
			out = append(out, a)
		}
	} else {
		memLock.Lock()
		out = append(out, memAlerts...)
		memLock.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func main() {
	log.Println("Starting KubeCustos Backend Service...")
	connectDB()

	r := mux.NewRouter()

	// API Endpoints
	r.HandleFunc("/api/v1/events", handleEvents).Methods("POST")
	r.HandleFunc("/api/v1/alerts", handleGetAlerts).Methods("GET")
	r.HandleFunc("/health", handleHealth).Methods("GET")
	
	// Prometheus Metrics Endpoint
	r.Handle("/metrics", promhttp.Handler()).Methods("GET")
	// metrics handler registered

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
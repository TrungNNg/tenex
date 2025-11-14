package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"tenex/internal/data"
	"tenex/internal/sshdparser"
	"tenex/pkg/postgresclient"
	"tenex/pkg/worker"
	"time"
	"unicode/utf8"

	"github.com/alexedwards/scs/v2"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"
)

type config struct {
	port               string
	env                string
	serverIdleTimeout  int
	serverReadTimeout  int
	serverWriteTimeout int

	postgresDSN         string
	postgresMaxOpenConn int
	postgresMaxIdleConn int
	postgresMaxIdelTime int

	claudeAPI string
}

type application struct {
	cfg    *config
	server *http.Server
	db     *data.DB
	val    *validator.Validate
	sm     *scs.SessionManager
	p      *sshdparser.SSHDParser
}

func newApplication(cfg *config) *application {

	// init postgres
	postgresConfig := postgresclient.PostgresConfig{
		DSN:         cfg.postgresDSN,
		MaxOpenConn: cfg.postgresMaxOpenConn,
		MaxIdelConn: cfg.postgresMaxIdleConn,
		MaxIdleTime: cfg.postgresMaxIdelTime,
	}
	db := postgresclient.New(postgresConfig)
	slog.Info("connected to Postgres :)")

	// init model
	models := data.NewDB(db)

	// init validator
	v := validator.New()

	// init session manager
	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.IdleTimeout = 20 * time.Minute
	sessionManager.Cookie.Name = "session_id"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.Persist = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Cookie.Secure = false // no https for now

	// init sshd log parser
	p := sshdparser.New()

	// init application
	app := &application{
		cfg: cfg,
		db:  models,
		val: v,
		sm:  sessionManager,
		p:   p,
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", app.cfg.port),
		Handler:      sessionManager.LoadAndSave(app.routes()),
		IdleTimeout:  time.Duration(cfg.serverIdleTimeout) * time.Minute,
		ReadTimeout:  time.Duration(cfg.serverReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.serverWriteTimeout) * time.Second,
		ErrorLog:     slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}
	app.server = server
	return app
}

func (app *application) run() {
	shutdownError := make(chan error)
	go func() {
		defer func() {
			pv := recover()
			if pv != nil {
				slog.Error(fmt.Sprintf("%v", pv))
			}
		}()
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		s := <-quit

		slog.Info("shutting down server", "signal", s.String())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Shutdown() will return nil if the graceful shutdown was successful, else an error
		err := app.server.Shutdown(ctx)
		if err != nil {
			shutdownError <- err
		}

		// waiting for any background goroutines to complete their tasks.
		// send nil to shutdownError to signal shutdown complete
		slog.Info("wait for background tasks to complete")
		worker.Wait()
		slog.Info("all backgound task completed")
		shutdownError <- nil
	}()

	slog.Info("starting server", "addr", app.server.Addr, "env", app.cfg.env)
	err := app.server.ListenAndServe()
	// Calling Shutdown() on our server will cause ListenAndServe() to immediately
	// return a http.ErrServerClosed error. If the err is NOT ErrServerClosed that mean
	// graceful shutdown failed
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error(err.Error())
		os.Exit(1)
	}

	// If shutdownError got non-nil error it mean graceful shutdown failed
	err = <-shutdownError
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	slog.Info("stopped server", "address", app.server.Addr)
}

func (app *application) routes() http.Handler {
	router := httprouter.New()

	router.HandlerFunc(http.MethodGet, "/health", app.healthcheckHandler)
	router.HandlerFunc(http.MethodGet, "/test", app.test)

	router.HandlerFunc(http.MethodPost, "/signup", app.signup)
	router.HandlerFunc(http.MethodPost, "/login", app.login)
	router.HandlerFunc(http.MethodPost, "/logout", app.logout)

	router.HandlerFunc(http.MethodPost, "/upload", app.uploadFile)
	router.HandlerFunc(http.MethodPost, "/parse", app.parseFile)
	router.HandlerFunc(http.MethodPost, "/analyze", app.analyzeWithLLM)

	router.HandlerFunc(http.MethodGet, "/files", app.getAllFiles)

	// write test for application.go

	// local deploy using docker

	// make readme, record video, push to github, submit

	return app.enableCORS(router)
}

func (app *application) getAllFiles(w http.ResponseWriter, r *http.Request) {
	userID := app.sm.GetString(r.Context(), "userID")
	if userID == "" {
		app.invalidCredentials(w, r)
		return
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	files, err := app.db.Files.GetFilesByUserID(r.Context(), uid)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	app.writeJSON(w, 200, envelope{
		"files": files,
	}, nil)
}

func (app *application) signup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username        string `json:"username" validate:"required,min=3,max=20,alphanum"`
		Password        string `json:"password" validate:"required,min=3,max=20"`
		ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, "invalid json")
		return
	}

	if err := app.val.Struct(input); err != nil {
		validationErrors := err.(validator.ValidationErrors)

		e := validationErrors[0]
		field := strings.ToLower(e.Field())

		switch e.Tag() {
		case "required":
			app.errorResponse(w, r, http.StatusBadRequest, field+" is required")
		case "min":
			app.errorResponse(w, r, http.StatusBadRequest, field+" must be at least "+e.Param()+" characters")
		case "max":
			app.errorResponse(w, r, http.StatusBadRequest, field+" must be at most "+e.Param()+" characters")
		case "alphanum":
			app.errorResponse(w, r, http.StatusBadRequest, field+" must be alphanumeric")
		case "eqfield":
			app.errorResponse(w, r, http.StatusBadRequest, "passwords do not match")
		default:
			app.errorResponse(w, r, http.StatusBadRequest, field+" is invalid")
		}
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	_, err = app.db.Users.CreateUser(r.Context(), uuid.New(), input.Username, string(hashedPassword))
	if err != nil {
		if errors.Is(err, data.ErrUsernameAlreadyExist) {
			app.errorResponse(w, r, http.StatusConflict, "username already exists")
			return
		}
		app.errorResponse(w, r, http.StatusInternalServerError, "failed to create user")
		return
	}

	app.writeJSON(w, 200, envelope{
		"message": "Sucessfully created account, please login.",
	}, nil)
}

func (app *application) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username" validate:"required,min=3,max=20,alphanum"`
		Password string `json:"password" validate:"required,min=3,max=20"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, "invalid json")
		return
	}

	if input.Username == "" || input.Password == "" {
		app.errorResponse(w, r, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := app.db.Users.GetUserByUsername(r.Context(), input.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			app.invalidCredentials(w, r)
			return
		}
		app.serverErrorResponse(w, r, err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))
	if err != nil {
		app.invalidCredentials(w, r)
		return
	}

	app.sm.Put(r.Context(), "userID", user.ID.String())

	app.writeJSON(w, 200, envelope{
		"message": "logged in",
	}, nil)
}

func (app *application) uploadFile(w http.ResponseWriter, r *http.Request) {
	userID := app.sm.GetString(r.Context(), "userID")
	if userID == "" {
		app.invalidCredentials(w, r)
		return
	}

	// Max 10MB
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, "failed to parse form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, "no file uploaded")
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".txt" && ext != ".log" {
		app.errorResponse(w, r, http.StatusBadRequest, "only .txt and .log files are allowed")
		return
	}

	content, err := io.ReadAll(file)
	if err != nil {
		app.errorResponse(w, r, http.StatusInternalServerError, "failed to read file")
		return
	}

	// Only allow text file
	if !utf8.Valid(content) {
		app.errorResponse(w, r, http.StatusBadRequest, "file must be text file")
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	f, err := app.db.Files.CreateFile(r.Context(), uid, uuid.New(), header.Filename, content)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	app.writeJSON(w, 200, envelope{
		"file_id":  f.ID,
		"filename": header.Filename,
	}, nil)
}

func (app *application) parseFile(w http.ResponseWriter, r *http.Request) {
	userID := app.sm.GetString(r.Context(), "userID")
	if userID == "" {
		app.invalidCredentials(w, r)
		return
	}

	var input struct {
		FileID string `json:"file_id" validate:"required,uuid"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, "invalid json")
		return
	}

	// Get file from database
	fid, err := uuid.Parse(input.FileID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	file, err := app.db.Files.GetFileByID(r.Context(), fid, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			app.errorResponse(w, r, http.StatusNotFound, "file not found")
			return
		}
		app.serverErrorResponse(w, r, err)
		return
	}

	// process file
	parsedEntries, _ := app.p.ParseFile(file.Data)

	// analyze file
	analysis := sshdparser.Analyze(parsedEntries)

	app.writeJSON(w, 200, envelope{
		"file_id":        file.ID,
		"analyze_result": analysis,
	}, nil)
}

func (app *application) analyzeWithLLM(w http.ResponseWriter, r *http.Request) {
	userID := app.sm.GetString(r.Context(), "userID")
	if userID == "" {
		app.invalidCredentials(w, r)
		return
	}

	var input struct {
		FileID string   `json:"file_id" validate:"required,uuid"`
		PIDs   []string `json:"pids" validate:"required,min=1"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.errorResponse(w, r, http.StatusBadRequest, "invalid json")
		return
	}

	if len(input.PIDs) == 0 {
		app.errorResponse(w, r, http.StatusBadRequest, "pids list cannot be empty")
		return
	}

	// Get file from database
	fid, err := uuid.Parse(input.FileID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	file, err := app.db.Files.GetFileByID(r.Context(), fid, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			app.errorResponse(w, r, http.StatusNotFound, "file not found")
			return
		}
		app.serverErrorResponse(w, r, err)
		return
	}

	pidSet := make(map[string]bool)
	for _, pid := range input.PIDs {
		pidSet[pid] = true
	}

	var matchedLines []string
	lines := strings.SplitSeq(string(file.Data), "\n")
	for line := range lines {
		for pid := range pidSet {
			if strings.Contains(line, fmt.Sprintf("sshd[%s]", pid)) {
				matchedLines = append(matchedLines, line)
				break
			}
		}
	}

	if len(matchedLines) == 0 {
		app.errorResponse(w, r, http.StatusNotFound, "no log lines found for provided PIDs")
		return
	}

	// Prepare prompt for LLM
	prompt := fmt.Sprintf(`You are a security analyst. Analyze these SSH log entries and explain why they are anomalous.

		Log entries (PIDs: %s):
		%s

		Provide:
		1. A brief explanation of why this is anomalous (2-3 sentences)
		2. A confidence score between 0.0 and 1.0

		Respond ONLY with valid JSON in this exact format:
		{
		  "explanation": "your explanation here",
		  "confidence": 0.95
		}`,
		strings.Join(input.PIDs, ", "),
		strings.Join(matchedLines, "\n"))

	response, err := app.callClaudeAPI(r.Context(), prompt)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	var result struct {
		Explanation string  `json:"explanation"`
		Confidence  float64 `json:"confidence"`
	}

	err = json.Unmarshal([]byte(response), &result)
	if err != nil {
		app.errorResponse(w, r, http.StatusInternalServerError, "failed to parse LLM response")
		return
	}

	app.writeJSON(w, 200, envelope{
		"explanation":   result.Explanation,
		"confidence":    result.Confidence,
		"matched_lines": len(matchedLines),
	}, nil)
}

func (app *application) callClaudeAPI(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1000,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", app.cfg.claudeAPI)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error: %s", string(body))
	}

	var apiResp struct {
		Content []struct {
			Text string `json:"text"`
			Type string `json:"type"`
		} `json:"content"`
	}

	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}

	// Extract text from response and clean any markdown formatting
	text := apiResp.Content[0].Text
	text = strings.TrimPrefix(text, "```json\n")
	text = strings.TrimSuffix(text, "\n```")
	text = strings.TrimSpace(text)

	return text, nil
}

func (app *application) test(w http.ResponseWriter, r *http.Request) {
	userID := app.sm.GetString(r.Context(), "userID")
	if userID == "" {
		app.invalidCredentials(w, r)
		return
	}
	//res, err := app.callClaudeAPI(r.Context(), "hello claude")
	//if err != nil {
	//	app.serverErrorResponse(w, r, err)
	//	return
	//}
	app.writeJSON(w, 200, envelope{
		"user_id": userID,
	}, nil)
}

func (app *application) logout(w http.ResponseWriter, r *http.Request) {
	err := app.sm.Destroy(r.Context())
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}
	app.writeJSON(w, 200, envelope{
		"message": "logged out",
	}, nil)
}

func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	env := envelope{
		"status": "available",
		"system_info": map[string]string{
			"environment": app.cfg.env,
		},
	}
	err := app.writeJSON(w, http.StatusOK, env, nil)
	if err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

func loadConfig() *config {
	err := godotenv.Load()
	if err != nil {
		slog.Info("No .env file found, using environment variables")
	}

	serverIdleTimeout, err := strconv.Atoi(os.Getenv("SERVER_IDLETIMEOUT"))
	if err != nil {
		slog.Error("Invalid SERVER_IDLETIMEOUT")
		os.Exit(1)
	}
	serverReadTimeout, err := strconv.Atoi(os.Getenv("SERVER_READTIMEOUT"))
	if err != nil {
		slog.Error("Invalid SERVER_READTIMEOUT")
		os.Exit(1)
	}
	serverWriteTimeout, err := strconv.Atoi(os.Getenv("SERVER_WRITETIMEOUT"))
	if err != nil {
		slog.Error("Invalid SERVER_WRITETIMEOUT")
		os.Exit(1)
	}

	postgresDSN := os.Getenv("POSTGRES_DSN")
	postgresMaxOpenConn, err := strconv.Atoi(os.Getenv("POSTGRES_MAXOPENCONN"))
	if err != nil {
		slog.Error("Invalid POSTGRES_MAXOPENCONN")
		os.Exit(1)
	}
	postgresMaxIdleConn, err := strconv.Atoi(os.Getenv("POSTGRES_MAXIDLECONN"))
	if err != nil {
		slog.Error("Invalid POSTGRES_MAXIDLECONN")
		os.Exit(1)
	}
	maxIdleTime, err := strconv.Atoi(os.Getenv("POSTGRES_MAXIDLETIME"))
	if err != nil {
		slog.Error("Invalid POSTGRES_MAXIDLETIME")
		os.Exit(1)
	}

	claudeAPI := os.Getenv("ANTHROPIC_API_KEY")

	return &config{
		env:                os.Getenv("ENV"),
		port:               os.Getenv("PORT"),
		serverIdleTimeout:  serverIdleTimeout,
		serverReadTimeout:  serverReadTimeout,
		serverWriteTimeout: serverWriteTimeout,

		postgresDSN:         postgresDSN,
		postgresMaxOpenConn: postgresMaxOpenConn,
		postgresMaxIdleConn: postgresMaxIdleConn,
		postgresMaxIdelTime: maxIdleTime,

		claudeAPI: claudeAPI,
	}
}

# SSH Log Analyzer

An AI-powered security analysis tool that automatically detects and explains suspicious activity in SSH authentication logs.

## Overview

This application allows users to upload [SSHD](https://man.openbsd.org/sshd) log files and receive instant analysis of potential security threats. Using LLM, it identifies anomalies like brute force attempts, invalid users, and suspicious access patterns, then provides detailed explanations with confidence ratings.

## Features

- **Automated Log Analysis**: Upload `.log` or `.txt` files for instant parsing and summarization
- **Anomaly Detection**: Identifies suspicious patterns including:
  - Failed authentication attempts
  - Invalid user login attempts
  - DNS warnings and connection anomalies
  - Repeated suspicious messages
  - Unauthorized access attempts
- **AI-Powered Insights**: Uses Claude API to analyze detected anomalies and provide:
  - Natural language explanations of threats
  - Confidence ratings for each anomaly
  - Context about matched log entries
- **Basic Authentication**: Secure user authentication with session management

## Tech Stack

**Backend:**
- Go (Golang)
- PostgreSQL
- Goose - Database migrations
- Claude API (Anthropic)

**Frontend:**
- React + TypeScript
- React Router
- Vite - Build tool and dev server

**Deployment:**
- Docker & Docker Compose - For local deployment

## Anomany Detection Approach and AI Model Usage
1. **Log Parsing**: Custom parser extracts structured data from SSH logs, identifying message types, IP addresses, timestamps, and process IDs.

2. **Pattern Detection**: Keep track of IP addresses that are associated with suspisus log messages such as:
   - Authentication failures per IP
   - Invalid username attempts
   - DNS resolution warnings
   - Max authentication failure message
   - Etc.

3. **Anomaly Aggregation**: Detected issues are grouped by IP address with associated metadata (PIDs, timestamps, usernames).

4. **AI Analysis**: For each anomaly, user can decide to have further analysis using LLM. The application do this by combine all relevant log lines using PIDs associated with the IP address. The LLM will answer the following:
   - Explain what the activity indicates
   - Assess the threat level
   - Provide security recommendations
   
   This approach prevent sending irrelevant info to LLM which help reduce cost and increase accuracy.

5. **Result Presentation**: Analysis results are displayed with confidence ratings, matched line counts, and actionable insights.

So this like a hybrid approach combines rule-based pattern detection (fast, deterministic) with AI interpretation (contextual, explanatory).

## Prerequisites

- Docker and Docker Compose installed
- **(Optional)** Claude API key from [Anthropic](https://console.anthropic.com/). The app can run without LLM feature.

## Setup and Installation

### 1. Clone the Repository
```bash
git clone https://github.com/TrungNNg/tenex.git
cd tenex
```

### 2. Configure Environment Variables (Optional)

Add your Claude API key to `.docker-compose.yml`
```env
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
```

### 3. Start the Application

In the root folder `tenex`, run all services (PostgreSQL, backend, frontend):
```bash
docker-compose up
```

### 4. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:4000

### 5. Test files
There are some example test files that can be uploaded to see how the application work.
```bash
test_full.log
test1.log
test2.log
test3.log
```
The `test_full.log` is taken from this [repo](https://github.com/logpai/loghub/tree/master/OpenSSH). The rest is just different part of the `test_full.log`

## Project Setup and Demo

Loom Video

## License

MIT

## Acknowledgments

- Anthropic for Claude API
- SSH log format test file https://github.com/logpai/loghub/tree/master
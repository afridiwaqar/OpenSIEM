#!/bin/bash
# OpenSIEM - GPL-3.0 Licensed
# Copyright (c) 2024–present
# See LICENSE for details.
# Array of sample log levels
levels=("info" "warn" "error" "debug")

# Array of sample messages
messages=(
  "User login attempt"
  "File not found"
  "Connection established"
  "Unexpected input"
  "Cache cleared"
  "Timeout occurred"
  "Configuration loaded"
  "Disk space low"
)

# Infinite loop to generate logs
while true; do
  # Pick a random level and message
  level=${levels[$RANDOM % ${#levels[@]}]}
  msg=${messages[$RANDOM % ${#messages[@]}]}

  # Add a random number to make it unique
  logger -p user.$level "$msg - ID:$RANDOM"

  # Control speed (adjust sleep for faster/slower logging)
  sleep 0.01
done


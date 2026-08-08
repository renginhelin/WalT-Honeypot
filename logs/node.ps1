#!/usr/bin/env pwsh

<# This powershell script is designed to fetch logs from a specific node using the WalT command-line tool. 
- I used this script because I use PuTTY to connect to our WalT server from my local Windows machine.
- It connects to our WalT server via PuTTY's plink.exe and retrieves logs related to "cowrie-attacks" 
  for the specified node. 
- The logs are saved locally in a JSON file to import the data into the database later on.
- NodeName, LocalPath, PlinkPath, SessionName and WaltCommand should be updated based on 
  your environment and needs. #> 

# Specify the node name for which you want to fetch logs. 
$NodeName = "pluto"

# 1. Set the local destination for the log file
$LocalPath = "<YOUR_PATH>\logs\${NodeName}-cowrie.json"

# 2. Define the path to PuTTY's execution tool
$PlinkPath = "C:\Program Files\PuTTY\plink.exe"

# 3. Enter the EXACT name of your saved PuTTY profile (case-sensitive)
$SessionName = "walt"

# --- START LOG STREAM ---
# Ask for the last specific time of history (e.g. -7d: for 7 days, -7h: for 7 hours, -7m: for 7 minutes).
$WaltCommand = 'yes "y" | walt log show --issuers $NodeName --history -7d: --streams "cowrie-attacks"'

Write-Host "Opening stream from WalT server... (Press Ctrl+C to stop)" -ForegroundColor Yellow

# Run the command once. 
& $PlinkPath -batch -load $SessionName $WaltCommand | Out-File -FilePath $LocalPath -Encoding utf8
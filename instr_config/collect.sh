#!/bin/bash
# collect.sh - CRITICAL for Labtainer grading
# Copies student artifacts from gateway_proxy home to grading directory
cp ~/findings.txt  $1/ 2>/dev/null
cp ~/sanitized.wav $1/ 2>/dev/null
cp ~/.bash_history $1/ 2>/dev/null

#!/usr/bin/env python3
"""
Fetch and parse Buildkite CI failures for the current branch.

Usage:
    python fetch_buildkite_failures.py [options]

Options:
    --branch BRANCH    Git branch (default: current branch)
    --build NUMBER     Specific build number (default: latest for branch)
    --pipeline SLUG    Pipeline slug (default: app)
    --help             Show this help message

Environment variables required:
    BUILDKITE_API_TOKEN
    BUILDKITE_ORGANIZATION_SLUG

Output: JSON with build info, failures, and summary
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error


def get_current_branch():
    """Get the current git branch name."""
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def api_request(url, token):
    """Make an authenticated request to the Buildkite API."""
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise SystemExit("Error: Invalid BUILDKITE_API_TOKEN")
        elif e.code == 404:
            return None
        raise


def fetch_raw_log(url, token):
    """Fetch raw log content from Buildkite."""
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError:
        return None


def strip_ansi_codes(text):
    """Remove ANSI escape codes from text."""
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_pattern.sub('', text)


def strip_buildkite_prefix(text):
    """Remove Buildkite timestamp prefixes."""
    # Remove \e_bk;t=<timestamp>\a prefix
    return re.sub(r'\x1b_bk;t=\d+\x07', '', text)


def normalize_log(text):
    """Clean up log text for parsing."""
    text = strip_buildkite_prefix(text)
    text = strip_ansi_codes(text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text


def parse_test_failures(log_content, job_name):
    """Extract test failures from log content."""
    errors = []
    normalized = normalize_log(log_content)
    
    # Rails/Minitest failure pattern
    minitest_pattern = re.compile(
        r'(?:Failure|Error):\s*\n'
        r'(\S+#\S+)\s*\[([^\]]+):(\d+)\]:\s*\n'
        r'((?:.*\n)*?)'
        r'(?=\n\n|\nbin/rails|\Z)',
        re.MULTILINE
    )
    
    for match in minitest_pattern.finditer(normalized):
        test_name = match.group(1)
        file_path = match.group(2)
        line_num = int(match.group(3))
        message = match.group(4).strip()
        
        errors.append({
            "test_name": test_name,
            "file": file_path,
            "line": line_num,
            "message": message[:500],  # Truncate long messages
            "type": "test_failure"
        })
    
    # RSpec failure pattern
    rspec_pattern = re.compile(
        r'(\d+)\)\s+(.+?)\n'
        r'\s+Failure/Error:.*?\n'
        r'((?:.*\n)*?)'
        r'\s+#\s+([^:]+):(\d+)',
        re.MULTILINE
    )
    
    for match in rspec_pattern.finditer(normalized):
        test_name = match.group(2).strip()
        message = match.group(3).strip()
        file_path = match.group(4)
        line_num = int(match.group(5))
        
        errors.append({
            "test_name": test_name,
            "file": file_path,
            "line": line_num,
            "message": message[:500],
            "type": "test_failure"
        })
    
    # Generic error pattern (catches exceptions)
    if not errors:
        error_pattern = re.compile(
            r'((?:ActiveRecord|NoMethodError|NameError|ArgumentError|RuntimeError|StandardError)'
            r'[^\n]+)\n((?:\s+from [^\n]+\n)*)',
            re.MULTILINE
        )
        
        for match in error_pattern.finditer(normalized):
            message = match.group(1)
            stack = match.group(2).strip()
            
            # Try to extract file/line from stack trace
            file_match = re.search(r'(?:app|test|spec)/[^:]+:(\d+)', stack)
            
            errors.append({
                "test_name": "Unknown",
                "file": file_match.group(0).split(':')[0] if file_match else None,
                "line": int(file_match.group(1)) if file_match else None,
                "message": message[:500],
                "type": "error"
            })
    
    return errors


def parse_lint_errors(log_content, job_name):
    """Extract linting errors from log content."""
    errors = []
    normalized = normalize_log(log_content)
    
    # Rubocop pattern
    rubocop_pattern = re.compile(
        r'^([^:\s]+):(\d+):\d+:\s*([CWEF]):\s*([^:]+):\s*(.+)$',
        re.MULTILINE
    )
    
    for match in rubocop_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "severity": match.group(3),
            "cop": match.group(4).strip(),
            "message": match.group(5).strip(),
            "type": "rubocop"
        })
    
    # Biome/ESLint pattern
    biome_pattern = re.compile(
        r'^([^:\s]+):(\d+)(?::\d+)?\s+(error|warning|info)\s+(.+)$',
        re.MULTILINE
    )
    
    for match in biome_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "severity": match.group(3),
            "message": match.group(4).strip(),
            "type": "lint"
        })
    
    return errors


def parse_typescript_errors(log_content, job_name):
    """Extract TypeScript compilation errors from log content."""
    errors = []
    normalized = normalize_log(log_content)
    
    # TypeScript error pattern
    ts_pattern = re.compile(
        r'^([^:\s]+\.tsx?)\((\d+),\d+\):\s*error\s+TS(\d+):\s*(.+)$',
        re.MULTILINE
    )
    
    for match in ts_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "code": f"TS{match.group(3)}",
            "message": match.group(4).strip(),
            "type": "typescript"
        })
    
    return errors


def classify_job(job_name):
    """Classify a job by its name to determine parsing strategy."""
    name_lower = job_name.lower()
    
    if any(x in name_lower for x in ['test', 'rspec', 'rails', 'minitest']):
        return 'test'
    elif any(x in name_lower for x in ['lint', 'rubocop', 'biome', 'eslint']):
        return 'lint'
    elif any(x in name_lower for x in ['typescript', 'typecheck', 'tsc']):
        return 'typescript'
    else:
        return 'unknown'


def parse_job_log(log_content, job_name):
    """Parse a job's log and extract relevant errors."""
    job_type = classify_job(job_name)
    
    if job_type == 'test':
        return parse_test_failures(log_content, job_name)
    elif job_type == 'lint':
        return parse_lint_errors(log_content, job_name)
    elif job_type == 'typescript':
        return parse_typescript_errors(log_content, job_name)
    else:
        # Try all parsers for unknown job types
        errors = []
        errors.extend(parse_test_failures(log_content, job_name))
        errors.extend(parse_lint_errors(log_content, job_name))
        errors.extend(parse_typescript_errors(log_content, job_name))
        return errors


def main():
    parser = argparse.ArgumentParser(
        description="Fetch and parse Buildkite CI failures"
    )
    parser.add_argument("--branch", help="Git branch (default: current)")
    parser.add_argument("--build", type=int, help="Specific build number")
    parser.add_argument("--pipeline", default="app", help="Pipeline slug (default: app)")
    
    args = parser.parse_args()
    
    # Check environment variables
    token = os.environ.get("BUILDKITE_API_TOKEN")
    org = os.environ.get("BUILDKITE_ORGANIZATION_SLUG")
    
    if not token:
        print(json.dumps({"error": "BUILDKITE_API_TOKEN environment variable not set"}))
        sys.exit(1)
    
    if not org:
        print(json.dumps({"error": "BUILDKITE_ORGANIZATION_SLUG environment variable not set"}))
        sys.exit(1)
    
    # Determine branch
    branch = args.branch or get_current_branch()
    if not branch:
        print(json.dumps({"error": "Could not determine git branch. Use --branch to specify."}))
        sys.exit(1)
    
    base_url = f"https://api.buildkite.com/v2/organizations/{org}/pipelines/{args.pipeline}"
    
    # Fetch build
    if args.build:
        build_url = f"{base_url}/builds/{args.build}"
        build = api_request(build_url, token)
    else:
        builds_url = f"{base_url}/builds?branch={branch}&per_page=1"
        builds = api_request(builds_url, token)
        if not builds:
            print(json.dumps({
                "error": f"No builds found for branch '{branch}' in pipeline '{args.pipeline}'"
            }))
            sys.exit(1)
        build = builds[0]
    
    if not build:
        print(json.dumps({"error": f"Build not found"}))
        sys.exit(1)
    
    # Extract failed jobs
    failed_jobs = [
        job for job in build.get("jobs", [])
        if job.get("state") == "failed" and job.get("type") == "script"
    ]
    
    result = {
        "build": {
            "number": build.get("number"),
            "branch": build.get("branch"),
            "state": build.get("state"),
            "commit": build.get("commit", "")[:8],
            "web_url": build.get("web_url"),
            "message": build.get("message", "")[:100]
        },
        "failures": [],
        "summary": {
            "total_failed_jobs": len(failed_jobs),
            "test_failures": 0,
            "lint_errors": 0,
            "typescript_errors": 0,
            "other_errors": 0
        }
    }
    
    # If build passed, report that
    if build.get("state") == "passed":
        result["message"] = "Build passed! No failures to diagnose."
        print(json.dumps(result, indent=2))
        return
    
    if build.get("state") == "running":
        result["message"] = "Build is still running."
        result["running_jobs"] = [
            job.get("name") for job in build.get("jobs", [])
            if job.get("state") == "running"
        ]
    
    # Process each failed job
    for job in failed_jobs:
        job_name = job.get("name", "Unknown")
        raw_log_url = job.get("raw_log_url")
        
        failure = {
            "job_name": job_name,
            "job_id": job.get("id"),
            "web_url": job.get("web_url"),
            "errors": []
        }
        
        if raw_log_url:
            log_content = fetch_raw_log(raw_log_url, token)
            if log_content:
                errors = parse_job_log(log_content, job_name)
                failure["errors"] = errors
                
                # Update summary counts
                for error in errors:
                    error_type = error.get("type", "other")
                    if error_type in ["test_failure", "error"]:
                        result["summary"]["test_failures"] += 1
                    elif error_type in ["rubocop", "lint"]:
                        result["summary"]["lint_errors"] += 1
                    elif error_type == "typescript":
                        result["summary"]["typescript_errors"] += 1
                    else:
                        result["summary"]["other_errors"] += 1
        
        result["failures"].append(failure)
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

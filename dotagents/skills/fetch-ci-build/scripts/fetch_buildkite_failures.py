#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Fetch and parse Buildkite CI failures for the current branch.

Usage:
    uv run {baseDir}/scripts/fetch_buildkite_failures.py [options]

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


def parse_python_errors(log_content, job_name):
    """Extract Python tool errors (uv, ruff, pytest, ty, pyproject-fmt)."""
    errors = []
    normalized = normalize_log(log_content)
    
    # uv error pattern (e.g., "error: Failed to initialize cache at `/.cache/uv`")
    uv_pattern = re.compile(
        r'^error:\s*(.+?)$(?:\n\s+Caused by:\s*(.+?)$)?',
        re.MULTILINE
    )
    
    for match in uv_pattern.finditer(normalized):
        message = match.group(1).strip()
        caused_by = match.group(2).strip() if match.group(2) else None
        full_message = f"{message} - Caused by: {caused_by}" if caused_by else message
        
        errors.append({
            "message": full_message[:500],
            "type": "uv"
        })
    
    # ruff error pattern (file:line:col: error code message)
    ruff_pattern = re.compile(
        r'^([^:\s]+\.py):(\d+):(\d+):\s*([A-Z]+\d+)\s+(.+)$',
        re.MULTILINE
    )
    
    for match in ruff_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "column": int(match.group(3)),
            "code": match.group(4),
            "message": match.group(5).strip(),
            "type": "ruff"
        })
    
    # pytest failure pattern
    pytest_pattern = re.compile(
        r'FAILED\s+([^:\s]+)::(\S+)',
        re.MULTILINE
    )
    
    for match in pytest_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "test_name": match.group(2),
            "type": "pytest"
        })
    
    # ty (type checker) error pattern
    ty_pattern = re.compile(
        r'^([^:\s]+\.py):(\d+):(\d+):\s*error:\s*(.+)$',
        re.MULTILINE
    )
    
    for match in ty_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "column": int(match.group(3)),
            "message": match.group(4).strip(),
            "type": "ty"
        })
    
    return errors


def parse_go_errors(log_content, job_name):
    """Extract Go tool errors (gofmt, go test)."""
    errors = []
    normalized = normalize_log(log_content)
    
    # gofmt outputs files that need formatting (one per line)
    # If gofmt -l outputs anything, those files need formatting
    gofmt_pattern = re.compile(
        r'^([^:\s]+\.go)$',
        re.MULTILINE
    )
    
    # Only capture if it looks like gofmt output (near "gofmt" in log)
    if 'gofmt' in normalized:
        for match in gofmt_pattern.finditer(normalized):
            filepath = match.group(1)
            if not filepath.startswith('/') and filepath.endswith('.go'):
                errors.append({
                    "file": filepath,
                    "message": "File needs formatting (gofmt)",
                    "type": "gofmt"
                })
    
    # go test failure pattern
    go_test_pattern = re.compile(
        r'---\s*FAIL:\s*(\S+)\s*\(([^)]+)\)',
        re.MULTILINE
    )
    
    for match in go_test_pattern.finditer(normalized):
        errors.append({
            "test_name": match.group(1),
            "duration": match.group(2),
            "type": "go_test"
        })
    
    # go build/compile errors
    go_compile_pattern = re.compile(
        r'^([^:\s]+\.go):(\d+):(\d+):\s*(.+)$',
        re.MULTILINE
    )
    
    for match in go_compile_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "column": int(match.group(3)),
            "message": match.group(4).strip(),
            "type": "go_compile"
        })
    
    return errors


def parse_docker_errors(log_content, job_name):
    """Extract Docker and permission errors."""
    errors = []
    normalized = normalize_log(log_content)
    
    # Permission denied errors - capture the full context line
    permission_pattern = re.compile(
        r'([^\n]*(?:Permission denied|permission denied)[^\n]*)',
        re.MULTILINE | re.IGNORECASE
    )
    
    for match in permission_pattern.finditer(normalized):
        message = match.group(1).strip()
        # Skip if it's just noise or already captured by another parser
        if message and len(message) > 20 and '^^^' not in message:
            errors.append({
                "message": message[:500],
                "type": "permission"
            })
    
    # Docker run failures
    docker_error_pattern = re.compile(
        r'docker:\s*Error[^:]*:\s*(.+?)(?=\n|$)',
        re.MULTILINE | re.IGNORECASE
    )
    
    for match in docker_error_pattern.finditer(normalized):
        errors.append({
            "message": match.group(1).strip(),
            "type": "docker"
        })
    
    # Generic "The command exited with status X" 
    exit_status_pattern = re.compile(
        r'The command exited with status (\d+)',
        re.MULTILINE
    )
    
    for match in exit_status_pattern.finditer(normalized):
        status = int(match.group(1))
        if status != 0 and not errors:  # Only add if no other errors found
            errors.append({
                "message": f"Command exited with status {status}",
                "exit_status": status,
                "type": "exit_status"
            })
    
    return errors


def classify_job(job_name):
    """Classify a job by its name to determine parsing strategy."""
    name_lower = job_name.lower()
    
    if any(x in name_lower for x in ['rspec', 'rails', 'minitest']):
        return 'ruby_test'
    elif any(x in name_lower for x in ['python', 'pytest', 'agents', 'snake']):
        return 'python'
    elif any(x in name_lower for x in ['go ', 'golang', 'cli test']):
        return 'go'
    elif any(x in name_lower for x in ['lint', 'rubocop', 'biome', 'eslint']):
        return 'lint'
    elif any(x in name_lower for x in ['typescript', 'typecheck', 'tsc']):
        return 'typescript'
    elif 'test' in name_lower:
        return 'test'
    else:
        return 'unknown'


def parse_job_log(log_content, job_name):
    """Parse a job's log and extract relevant errors."""
    job_type = classify_job(job_name)
    errors = []
    
    # Always check for Docker/permission errors first
    errors.extend(parse_docker_errors(log_content, job_name))
    
    if job_type == 'ruby_test':
        errors.extend(parse_test_failures(log_content, job_name))
    elif job_type == 'python':
        errors.extend(parse_python_errors(log_content, job_name))
    elif job_type == 'go':
        errors.extend(parse_go_errors(log_content, job_name))
    elif job_type == 'lint':
        errors.extend(parse_lint_errors(log_content, job_name))
    elif job_type == 'typescript':
        errors.extend(parse_typescript_errors(log_content, job_name))
    elif job_type == 'test':
        # Generic test - try multiple parsers
        errors.extend(parse_test_failures(log_content, job_name))
        errors.extend(parse_python_errors(log_content, job_name))
        errors.extend(parse_go_errors(log_content, job_name))
    else:
        # Unknown - try all parsers
        errors.extend(parse_test_failures(log_content, job_name))
        errors.extend(parse_lint_errors(log_content, job_name))
        errors.extend(parse_typescript_errors(log_content, job_name))
        errors.extend(parse_python_errors(log_content, job_name))
        errors.extend(parse_go_errors(log_content, job_name))
    
    # Deduplicate errors by message
    seen = set()
    unique_errors = []
    for error in errors:
        key = error.get('message', '') or error.get('test_name', '') or error.get('file', '')
        if key and key not in seen:
            seen.add(key)
            unique_errors.append(error)
        elif not key:
            unique_errors.append(error)
    
    return unique_errors


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
            "python_errors": 0,
            "go_errors": 0,
            "docker_errors": 0,
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
                    if error_type in ["test_failure", "error", "pytest"]:
                        result["summary"]["test_failures"] += 1
                    elif error_type in ["rubocop", "lint", "ruff"]:
                        result["summary"]["lint_errors"] += 1
                    elif error_type == "typescript":
                        result["summary"]["typescript_errors"] += 1
                    elif error_type in ["uv", "ty"]:
                        result["summary"]["python_errors"] += 1
                    elif error_type in ["go_test", "go_compile", "gofmt"]:
                        result["summary"]["go_errors"] += 1
                    elif error_type in ["docker", "permission", "exit_status"]:
                        result["summary"]["docker_errors"] += 1
                    else:
                        result["summary"]["other_errors"] += 1
        
        result["failures"].append(failure)
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

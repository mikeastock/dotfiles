#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Fetch and parse CircleCI failures for the current branch.

Usage:
    uv run {baseDir}/scripts/fetch_circleci_failures.py [options]

Options:
    --branch BRANCH      Git branch (default: current branch)
    --pipeline NUMBER    Specific pipeline number
    --project SLUG       Project slug (default: auto-detect from git remote)
                         Format: gh/owner/repo or bb/owner/repo
    --help               Show this help message

Environment variables required:
    CIRCLECI_TOKEN       Personal API token

Output: JSON with pipeline info, failures, and summary
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


def get_project_slug():
    """Auto-detect project slug from git remote."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True
        )
        url = result.stdout.strip()
        
        # Parse GitHub SSH URL: git@github.com:owner/repo.git
        match = re.match(r'git@github\.com:([^/]+)/(.+?)(?:\.git)?$', url)
        if match:
            return f"gh/{match.group(1)}/{match.group(2)}"
        
        # Parse GitHub HTTPS URL: https://github.com/owner/repo.git
        match = re.match(r'https://github\.com/([^/]+)/(.+?)(?:\.git)?$', url)
        if match:
            return f"gh/{match.group(1)}/{match.group(2)}"
        
        # Parse Bitbucket SSH URL: git@bitbucket.org:owner/repo.git
        match = re.match(r'git@bitbucket\.org:([^/]+)/(.+?)(?:\.git)?$', url)
        if match:
            return f"bb/{match.group(1)}/{match.group(2)}"
        
        # Parse Bitbucket HTTPS URL: https://bitbucket.org/owner/repo.git
        match = re.match(r'https://bitbucket\.org/([^/]+)/(.+?)(?:\.git)?$', url)
        if match:
            return f"bb/{match.group(1)}/{match.group(2)}"
        
        return None
    except subprocess.CalledProcessError:
        return None


def api_request(url, token):
    """Make an authenticated request to the CircleCI API."""
    req = urllib.request.Request(url)
    req.add_header("Circle-Token", token)
    req.add_header("Accept", "application/json")
    
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise SystemExit("Error: Invalid CIRCLECI_TOKEN")
        elif e.code == 404:
            return None
        raise


def fetch_job_log(project_slug, job_number, token):
    """Fetch job output/log from CircleCI."""
    # Get job details which includes step actions
    url = f"https://circleci.com/api/v2/project/{project_slug}/job/{job_number}"
    job_details = api_request(url, token)
    
    if not job_details:
        return None
    
    # Collect output from all steps
    log_content = []
    
    # The v2 API doesn't directly expose logs, we need to use v1.1 API for step output
    # v1.1 endpoint: GET /project/:vcs-type/:username/:project/:build_num
    parts = project_slug.split('/')
    if len(parts) != 3:
        return None
    
    vcs_type = "github" if parts[0] == "gh" else "bitbucket"
    v1_url = f"https://circleci.com/api/v1.1/project/{vcs_type}/{parts[1]}/{parts[2]}/{job_number}"
    
    req = urllib.request.Request(v1_url)
    req.add_header("Circle-Token", token)
    req.add_header("Accept", "application/json")
    
    try:
        with urllib.request.urlopen(req) as response:
            build_details = json.loads(response.read().decode())
    except urllib.error.HTTPError:
        return None
    
    # Extract step outputs
    steps = build_details.get("steps", [])
    for step in steps:
        for action in step.get("actions", []):
            if action.get("output_url"):
                # Fetch the actual output
                try:
                    output_req = urllib.request.Request(action["output_url"])
                    with urllib.request.urlopen(output_req) as resp:
                        output_data = json.loads(resp.read().decode())
                        for item in output_data:
                            if item.get("message"):
                                log_content.append(item["message"])
                except (urllib.error.HTTPError, json.JSONDecodeError):
                    pass
    
    return "\n".join(log_content) if log_content else None


def strip_ansi_codes(text):
    """Remove ANSI escape codes from text."""
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_pattern.sub('', text)


def normalize_log(text):
    """Clean up log text for parsing."""
    text = strip_ansi_codes(text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text


def parse_test_failures(log_content):
    """Extract test failures from log content."""
    errors = []
    normalized = normalize_log(log_content)
    
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
    
    # pytest short test summary with error details
    pytest_error_pattern = re.compile(
        r'FAILED\s+([^:\s]+)::(\S+)\s*-\s*(.+)$',
        re.MULTILINE
    )
    
    for match in pytest_error_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "test_name": match.group(2),
            "message": match.group(3).strip()[:500],
            "type": "pytest"
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
        errors.append({
            "test_name": match.group(2).strip(),
            "file": match.group(4),
            "line": int(match.group(5)),
            "message": match.group(3).strip()[:500],
            "type": "test_failure"
        })
    
    # Jest/Mocha failure pattern
    jest_pattern = re.compile(
        r'●\s+(.+?)\n\s*\n\s*(.+?)(?=\n\s*\n|\n\s*●|\Z)',
        re.MULTILINE | re.DOTALL
    )
    
    for match in jest_pattern.finditer(normalized):
        errors.append({
            "test_name": match.group(1).strip(),
            "message": match.group(2).strip()[:500],
            "type": "jest"
        })
    
    # Generic assertion error
    assertion_pattern = re.compile(
        r'(AssertionError|assert\s+\w+.*?failed):\s*(.+?)(?=\n\n|\Z)',
        re.MULTILINE | re.IGNORECASE
    )
    
    for match in assertion_pattern.finditer(normalized):
        errors.append({
            "message": match.group(2).strip()[:500],
            "type": "assertion"
        })
    
    return errors


def parse_lint_errors(log_content):
    """Extract linting errors from log content."""
    errors = []
    normalized = normalize_log(log_content)
    
    # Generic file:line:col pattern (eslint, ruff, rubocop, etc.)
    lint_pattern = re.compile(
        r'^([^:\s]+):(\d+):(\d+):\s*(?:(error|warning|Error|Warning|E|W|C|F))?\s*(.+)$',
        re.MULTILINE
    )
    
    for match in lint_pattern.finditer(normalized):
        errors.append({
            "file": match.group(1),
            "line": int(match.group(2)),
            "column": int(match.group(3)),
            "severity": match.group(4) or "error",
            "message": match.group(5).strip()[:500],
            "type": "lint"
        })
    
    return errors


def parse_typescript_errors(log_content):
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


def parse_build_errors(log_content):
    """Extract build/compilation errors."""
    errors = []
    normalized = normalize_log(log_content)
    
    # Generic error pattern
    error_pattern = re.compile(
        r'^(error|Error|ERROR):\s*(.+)$',
        re.MULTILINE
    )
    
    for match in error_pattern.finditer(normalized):
        message = match.group(2).strip()
        if message and len(message) > 10:
            errors.append({
                "message": message[:500],
                "type": "build_error"
            })
    
    # Exit code pattern
    exit_pattern = re.compile(
        r'(?:exited with|exit code|returned)\s+(\d+)',
        re.MULTILINE | re.IGNORECASE
    )
    
    for match in exit_pattern.finditer(normalized):
        code = int(match.group(1))
        if code != 0:
            errors.append({
                "message": f"Process exited with code {code}",
                "exit_code": code,
                "type": "exit_status"
            })
    
    return errors


def parse_job_log(log_content, job_name):
    """Parse a job's log and extract relevant errors."""
    errors = []
    
    # Try all parsers
    errors.extend(parse_test_failures(log_content))
    errors.extend(parse_lint_errors(log_content))
    errors.extend(parse_typescript_errors(log_content))
    errors.extend(parse_build_errors(log_content))
    
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
        description="Fetch and parse CircleCI failures"
    )
    parser.add_argument("--branch", help="Git branch (default: current)")
    parser.add_argument("--pipeline", type=int, help="Specific pipeline number")
    parser.add_argument("--project", help="Project slug (e.g., gh/owner/repo)")
    
    args = parser.parse_args()
    
    # Check environment variables
    token = os.environ.get("CIRCLECI_TOKEN")
    
    if not token:
        print(json.dumps({"error": "CIRCLECI_TOKEN environment variable not set"}))
        sys.exit(1)
    
    # Determine project
    project_slug = args.project or get_project_slug()
    if not project_slug:
        print(json.dumps({
            "error": "Could not determine project. Use --project to specify (e.g., gh/owner/repo)"
        }))
        sys.exit(1)
    
    # Determine branch
    branch = args.branch or get_current_branch()
    if not branch:
        print(json.dumps({"error": "Could not determine git branch. Use --branch to specify."}))
        sys.exit(1)
    
    base_url = "https://circleci.com/api/v2"
    
    # Fetch pipeline
    if args.pipeline:
        # Get pipelines and find the one with matching number
        pipelines_url = f"{base_url}/project/{project_slug}/pipeline?branch={branch}"
        response = api_request(pipelines_url, token)
        pipelines = response.get("items", []) if response else []
        pipeline = next((p for p in pipelines if p.get("number") == args.pipeline), None)
    else:
        # Get latest pipeline for branch
        pipelines_url = f"{base_url}/project/{project_slug}/pipeline?branch={branch}"
        response = api_request(pipelines_url, token)
        pipelines = response.get("items", []) if response else []
        pipeline = pipelines[0] if pipelines else None
    
    if not pipeline:
        print(json.dumps({
            "error": f"No pipelines found for branch '{branch}' in project '{project_slug}'"
        }))
        sys.exit(1)
    
    pipeline_id = pipeline.get("id")
    
    # Get workflows for this pipeline
    workflows_url = f"{base_url}/pipeline/{pipeline_id}/workflow"
    workflows_response = api_request(workflows_url, token)
    workflows = workflows_response.get("items", []) if workflows_response else []
    
    result = {
        "pipeline": {
            "id": pipeline_id,
            "number": pipeline.get("number"),
            "branch": branch,
            "state": pipeline.get("state"),
            "web_url": f"https://app.circleci.com/pipelines/{project_slug}/{pipeline.get('number')}"
        },
        "failures": [],
        "summary": {
            "total_failed_jobs": 0,
            "test_failures": 0,
            "lint_errors": 0,
            "typescript_errors": 0,
            "build_errors": 0,
            "other_errors": 0
        }
    }
    
    # Check if all workflows passed
    all_passed = all(w.get("status") == "success" for w in workflows)
    if all_passed and workflows:
        result["message"] = "All workflows passed! No failures to diagnose."
        print(json.dumps(result, indent=2))
        return
    
    # Check if still running
    any_running = any(w.get("status") == "running" for w in workflows)
    if any_running:
        result["message"] = "Some workflows are still running."
        result["running_workflows"] = [
            w.get("name") for w in workflows if w.get("status") == "running"
        ]
    
    # Process each workflow
    for workflow in workflows:
        if workflow.get("status") not in ["failed", "error"]:
            continue
        
        workflow_id = workflow.get("id")
        
        # Get jobs for this workflow
        jobs_url = f"{base_url}/workflow/{workflow_id}/job"
        jobs_response = api_request(jobs_url, token)
        jobs = jobs_response.get("items", []) if jobs_response else []
        
        # Filter to failed jobs
        failed_jobs = [j for j in jobs if j.get("status") == "failed"]
        result["summary"]["total_failed_jobs"] += len(failed_jobs)
        
        for job in failed_jobs:
            job_name = job.get("name", "Unknown")
            job_number = job.get("job_number")
            
            failure = {
                "workflow": workflow.get("name"),
                "job_name": job_name,
                "job_number": job_number,
                "web_url": f"https://app.circleci.com/pipelines/{project_slug}/{pipeline.get('number')}/workflows/{workflow_id}/jobs/{job_number}",
                "errors": []
            }
            
            # Try to fetch and parse job logs
            if job_number:
                log_content = fetch_job_log(project_slug, job_number, token)
                if log_content:
                    errors = parse_job_log(log_content, job_name)
                    failure["errors"] = errors
                    
                    # Update summary counts
                    for error in errors:
                        error_type = error.get("type", "other")
                        if error_type in ["test_failure", "pytest", "jest", "assertion"]:
                            result["summary"]["test_failures"] += 1
                        elif error_type == "lint":
                            result["summary"]["lint_errors"] += 1
                        elif error_type == "typescript":
                            result["summary"]["typescript_errors"] += 1
                        elif error_type in ["build_error", "exit_status"]:
                            result["summary"]["build_errors"] += 1
                        else:
                            result["summary"]["other_errors"] += 1
            
            result["failures"].append(failure)
    
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

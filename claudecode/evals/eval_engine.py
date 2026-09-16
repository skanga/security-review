"""Evaluation engine for running SAST security audits on GitHub PRs."""

import os
import sys
import subprocess
import shutil
import time
import threading
import uuid
import re
import base64
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from pathlib import Path

from ..json_parser import parse_json_with_fallbacks, is_completed_report

# Timeout constants (in seconds)
TIMEOUT_SHORT = 10
TIMEOUT_GIT_OPERATION = 60
TIMEOUT_FETCH = 600
TIMEOUT_CLONE = 300
TIMEOUT_WORKTREE = 300
TIMEOUT_WORKTREE_CREATE = 1200
TIMEOUT_CLAUDECODE = 1800


@dataclass
class EvalCase:
    """Single evaluation test case."""
    repo_name: str
    pr_number: int
    description: str = ""


@dataclass
class EvalResult:
    """Result of a single evaluation."""
    repo_name: str
    pr_number: int
    description: str
    
    # Evaluation results
    success: bool
    runtime_seconds: float
    findings_count: int
    detected_vulnerabilities: bool
    
    # Optional fields
    error_message: str = ""
    findings_summary: Optional[List[Dict[str, Any]]] = None
    full_findings: Optional[List[Dict[str, Any]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class EvaluationEngine:
    """Engine for running security evaluations on GitHub PRs."""
    
    def __init__(self, work_dir: str = None, verbose: bool = False):
        """Initialize evaluation engine.
        
        Args:
            work_dir: Directory for cloning repositories
            verbose: Enable verbose logging
        """
        # Use ~/code/audit as base directory like pr_audit does
        if work_dir is None:
            work_dir = os.path.expanduser("~/code/audit")
        self.work_dir = str(Path(work_dir).resolve())
        self._owned_worktrees = {}
        Path(self.work_dir).mkdir(parents=True, exist_ok=True)
        
        self.verbose = verbose
        self.claude_api_key = os.environ.get('ANTHROPIC_API_KEY', '')
        
        if not self.claude_api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable required")
        
        # Repository locks for concurrent access
        self._repo_locks: Dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()

        # Get GitHub token from environment or gh CLI
        self.github_token = os.environ.get('GITHUB_TOKEN', '')
        if not self.github_token:
            try:
                result = subprocess.run(['gh', 'auth', 'token'], 
                                      capture_output=True, text=True, timeout=TIMEOUT_GIT_OPERATION)
                if result.returncode == 0:
                    self.github_token = result.stdout.strip()
                    self.log("Retrieved GitHub token from gh CLI")
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                self.log(f"Could not retrieve GitHub token from gh CLI: {e}")

    
    def log(self, message: str, prefix: str = "[EVAL]") -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            timestamp = time.strftime('%H:%M:%S')
            print(f"{prefix} [{timestamp}] {message}", file=sys.stderr)
    
    def _get_repo_lock(self, repo_name: str) -> threading.Lock:
        """Get or create a lock for a repository.
        
        Args:
            repo_name: Repository name
            
        Returns:
            Lock for the repository
        """
        with self._locks_lock:
            if repo_name not in self._repo_locks:
                self._repo_locks[repo_name] = threading.Lock()
            return self._repo_locks[repo_name]
    
    def _clean_worktrees(self, repo_path: str, branch_pattern: str = None) -> None:
        """Never infer ownership from branch names or Git's locked flag.

        Only _cleanup_worktree may release resources recorded by this instance.
        Orphans from earlier processes require explicit operator recovery.
        """
        return

    def _get_eval_branch_name(self, test_case: EvalCase) -> str:
        """Generate a branch name for evaluation.
        
        Args:
            test_case: Test case being evaluated
            
        Returns:
            Branch name for the evaluation
        """
        # Create a safe branch name from repo and PR
        safe_repo = test_case.repo_name.replace('/', '-').replace('.', '-')
        timestamp = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:12]
        return f"eval-pr-{safe_repo}-{test_case.pr_number}-{timestamp}"
    
    def _setup_repository(self, test_case: EvalCase) -> Tuple[bool, str, str]:
        """Set up repository worktree for PR evaluation.
        
        Args:
            test_case: Test case containing repo and PR info
            
        Returns:
            Tuple of (success, worktree_path, error_message)
        """
        repo_name = test_case.repo_name
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo_name):
            raise ValueError('Invalid GitHub repository')
        pr_number = test_case.pr_number
        
        # Create base path for this repository
        safe_repo_name = repo_name.replace('/', '_')
        base_repo_path = os.path.join(self.work_dir, safe_repo_name)
        
        # Get lock for this repository
        repo_lock = self._get_repo_lock(repo_name)
        git_env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
        git_env['GIT_TERMINAL_PROMPT'] = '0'
        if self.github_token:
            authorization = base64.b64encode(('x-access-token:' + self.github_token).encode()).decode()
            git_env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
                           GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + authorization)
        
        with repo_lock:
            # Clone or update the base repository
            if not os.path.exists(base_repo_path):
                self.log(f"Cloning {repo_name} to {base_repo_path}")
                clone_url = f"https://github.com/{repo_name}.git"
                
                try:
                    subprocess.run(['git', 'clone', '--filter=blob:none', clone_url, base_repo_path],
                                 check=True, capture_output=True, timeout=TIMEOUT_CLONE, env=git_env)
                except subprocess.CalledProcessError as e:
                    error_msg = "Failed to clone repository; check permissions and network"
                    self.log(error_msg)
                    return False, "", error_msg
            
            # Clean up any stale worktrees for this evaluation
            eval_branch_prefix = f"eval-pr-{safe_repo_name}-{pr_number}"
            self._clean_worktrees(base_repo_path, eval_branch_prefix)
            
            # Create worktree for this specific evaluation
            eval_branch = self._get_eval_branch_name(test_case)
            worktree_path = os.path.join(self.work_dir, f"{safe_repo_name}_pr{pr_number}_{uuid.uuid4().hex}")
            
            self._owned_worktrees[str(Path(worktree_path).absolute())] = (base_repo_path, eval_branch)
            try:
                # Fetch the PR
                self.log(f"Fetching PR #{pr_number} from {repo_name}")
                subprocess.run(['git', '-C', base_repo_path, 'fetch', 'origin', f'pull/{pr_number}/head'],
                             check=True, capture_output=True, timeout=TIMEOUT_FETCH, env=git_env)
                
                # Create new worktree with PR changes
                self.log(f"Creating worktree at {worktree_path}")
                subprocess.run(['git', '-C', base_repo_path, 'worktree', 'add', '-b', eval_branch, 
                              worktree_path, 'FETCH_HEAD'],
                             check=True, capture_output=True, timeout=TIMEOUT_WORKTREE_CREATE)
                
                return True, worktree_path, ""
                
            except subprocess.CalledProcessError as e:
                error_msg = "Failed to set up owned evaluation worktree"
                self.log(error_msg)
                
                # Preserve failed owned worktree for explicit recovery; never delete unknown paths.

                return False, "", error_msg
    
    def _cleanup_worktree(self, test_case: EvalCase, worktree_path: str) -> None:
        path = Path(worktree_path).absolute()
        owned = self._owned_worktrees.get(str(path))
        root = Path(self.work_dir).resolve()
        if not owned or path.is_symlink() or not path.resolve().is_relative_to(root) or path.resolve() == root:
            return
        base_repo_path, branch = owned
        with self._get_repo_lock(test_case.repo_name):
            result = subprocess.run(['git', '-C', base_repo_path, 'worktree', 'remove', '--force', str(path)],
                                    capture_output=True, check=False, timeout=TIMEOUT_WORKTREE)
            if result.returncode == 0:
                subprocess.run(['git', '-C', base_repo_path, 'branch', '-D', branch],
                               capture_output=True, check=False, timeout=TIMEOUT_SHORT)
                self._owned_worktrees.pop(str(path), None)

    def run_evaluation(self, test_case: EvalCase) -> EvalResult:
        """Run security evaluation on a single PR.
        
        Args:
            test_case: Test case to evaluate
            
        Returns:
            EvalResult with evaluation outcome
        """
        start_time = time.time()
        self.log(f"Starting evaluation of {test_case.repo_name}#{test_case.pr_number}")
        
        # Set up repository
        success, worktree_path, error_msg = self._setup_repository(test_case)
        if not success:
            return EvalResult(
                repo_name=test_case.repo_name,
                pr_number=test_case.pr_number,
                description=test_case.description,
                success=False,
                runtime_seconds=time.time() - start_time,
                findings_count=0,
                detected_vulnerabilities=False,
                error_message=f"Repository setup failed: {error_msg}"
            )
        
        try:
            # Run the SAST audit
            self.log(f"Running SAST audit on {worktree_path}")
            audit_success, output, parsed_results, error_message = self._run_sast_audit(test_case, worktree_path)
            
            if not audit_success:
                return EvalResult(
                    repo_name=test_case.repo_name,
                    pr_number=test_case.pr_number,
                    description=test_case.description,
                    success=False,
                    runtime_seconds=time.time() - start_time,
                    findings_count=0,
                    detected_vulnerabilities=False,
                    error_message=f"SAST audit failed: {error_message or 'Unknown error'}"
                )
            
            # Extract findings from results
            findings = []
            if parsed_results and 'findings' in parsed_results:
                findings = parsed_results['findings']
            
            findings_count = len(findings)
            detected_vulnerabilities = findings_count > 0
            
            # Create findings summary
            findings_summary = []
            for finding in findings[:10]:  # Limit to first 10 for summary
                summary_item = {
                    'file': finding.get('file', finding.get('path', 'unknown')),
                    'line': finding.get('line', finding.get('start', {}).get('line', 0)),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'title': finding.get('check_id', finding.get('category', 'Unknown')),
                    'description': finding.get('description', finding.get('message', 'Unknown'))
                }
                findings_summary.append(summary_item)
            
            return EvalResult(
                repo_name=test_case.repo_name,
                pr_number=test_case.pr_number,
                description=test_case.description,
                success=True,
                runtime_seconds=time.time() - start_time,
                findings_count=findings_count,
                detected_vulnerabilities=detected_vulnerabilities,
                findings_summary=findings_summary,
                full_findings=findings
            )
            
        finally:
            # Always clean up the worktree
            self._cleanup_worktree(test_case, worktree_path)
    
    def _run_sast_audit(self, test_case: EvalCase, repo_path: str) -> Tuple[bool, str, Optional[Dict[str, Any]], Optional[str]]:
        """Run the SAST audit script on a repository.
        
        Args:
            test_case: Test case being evaluated
            repo_path: Path to the repository
            
        Returns:
            Tuple of (success, output, parsed_results, error_message)
        """
        # Prepare environment
        env = os.environ.copy()
        env['GITHUB_REPOSITORY'] = test_case.repo_name
        env['PR_NUMBER'] = str(test_case.pr_number)
        env['ANTHROPIC_API_KEY'] = self.claude_api_key
        if self.github_token:
            env['GITHUB_TOKEN'] = self.github_token
        env['EVAL_MODE'] = '1'  # Enable eval mode
        
        # Run the audit script
        script_path = Path(__file__).parent.parent / 'github_action_audit.py'
        
        # Add the project root to PYTHONPATH so claudecode module can be imported
        project_root = script_path.parent.parent
        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] = f"{project_root}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env['PYTHONPATH'] = str(project_root)
        
        try:
            self.log(f"Executing SAST audit for PR #{test_case.pr_number}")
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=repo_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_CLAUDECODE
            )
            
            output = result.stdout
            
            # Parse the JSON output first to see if we got valid results
            success, parsed_results = parse_json_with_fallbacks(output)
            if not success:
                self.log("Failed to parse SAST audit output as JSON")
                # If we can't parse JSON and have non-zero exit code, it's a real failure
                if result.returncode != 0:
                    error_output = result.stderr or output
                    self.log(f"SAST audit failed with return code {result.returncode}")
                    self.log(f"Error output: {error_output[:500]}...")
                    return False, output, None, f"Exit code {result.returncode}: {error_output[:200]}"
                return False, output, None, "Invalid JSON output"
            
            # If we got valid JSON output, we consider it successful even with exit code 1
            # (exit code 1 means high-severity findings were found)
            if result.returncode not in [0, 1]:
                error_output = result.stderr or output
                self.log(f"SAST audit failed with unexpected return code {result.returncode}")
                self.log(f"Error output: {error_output[:500]}...")
                return False, output, None, f"Unexpected exit code {result.returncode}: {error_output[:200]}"
            
            if not is_completed_report(parsed_results):
                return False, output, parsed_results, "Invalid, failed, or incomplete security report"
            return True, output, parsed_results, None
            
        except subprocess.TimeoutExpired:
            self.log(f"SAST audit timed out after {TIMEOUT_CLAUDECODE} seconds")
            return False, "", None, f"Timeout after {TIMEOUT_CLAUDECODE} seconds"
        except Exception as e:
            self.log(f"Exception during SAST audit: {e}")
            return False, "", None, str(e)


def run_single_evaluation(test_case: EvalCase, verbose: bool = False, work_dir: str = None) -> EvalResult:
    """Convenience function to run a single evaluation.
    
    Args:
        test_case: Test case to evaluate
        verbose: Enable verbose logging
        work_dir: Directory for temporary files
        
    Returns:
        EvalResult
    """
    engine = EvaluationEngine(work_dir=work_dir, verbose=verbose)
    return engine.run_evaluation(test_case)

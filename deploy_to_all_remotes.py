#!/usr/bin/env python3
"""
Deploy OmicsOracle to all GitHub remotes
"""

import subprocess
import sys
from typing import List, Tuple

def run_command(command: str) -> Tuple[bool, str]:
    """Execute shell command and return success status and output"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)

def get_current_branch() -> str:
    """Get the current git branch name"""
    success, output = run_command("git rev-parse --abbrev-ref HEAD")
    if success:
        return output.strip()
    return "main"

def push_to_remote(remote_name: str, branch: str = None) -> bool:
    """Push current branch to specified remote"""
    if branch is None:
        branch = get_current_branch()
    
    print(f"📤 Pushing to remote '{remote_name}' (branch: {branch})...")
    
    success, output = run_command(f"git push {remote_name} {branch}")
    
    if success:
        print(f"✅ Successfully pushed to {remote_name}")
        return True
    else:
        print(f"❌ Failed to push to {remote_name}: {output}")
        return False

def push_to_all_remotes(branch: str = None) -> None:
    """Push to all configured remotes"""
    # Get list of remotes
    success, output = run_command("git remote")
    if not success:
        print("❌ Failed to get git remotes")
        sys.exit(1)
    
    remotes = [remote.strip() for remote in output.split('\n') if remote.strip()]
    
    if not remotes:
        print("❌ No git remotes configured")
        sys.exit(1)
    
    print(f"🚀 Deploying OmicsOracle to {len(remotes)} GitHub repositories...")
    print(f"📋 Configured remotes: {', '.join(remotes)}")
    
    current_branch = branch or get_current_branch()
    print(f"🌿 Current branch: {current_branch}")
    
    # Check for uncommitted changes
    success, output = run_command("git status --porcelain")
    if success and output.strip():
        print("⚠️  Warning: You have uncommitted changes:")
        print(output)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            print("Deployment cancelled")
            return
    
    # Push to each remote
    results = []
    for remote in remotes:
        success = push_to_remote(remote, current_branch)
        results.append((remote, success))
    
    # Summary
    print("\n📊 Deployment Summary:")
    print("=" * 50)
    
    successful = 0
    for remote, success in results:
        status = "✅ SUCCESS" if success else "❌ FAILED"  
        print(f"{remote:12} | {status}")
        if success:
            successful += 1
    
    print("=" * 50)
    print(f"Total: {successful}/{len(remotes)} repositories updated successfully")
    
    if successful == len(remotes):
        print("🎉 All repositories updated successfully!")
        print("\n🔗 Repository URLs:")
        for remote in remotes:
            success, url = run_command(f"git remote get-url {remote}")
            if success:
                print(f"  • {remote}: {url.strip()}")
    else:
        print("⚠️  Some deployments failed. Check the output above for details.")

def main():
    """Main deployment function"""
    if len(sys.argv) > 1:
        branch = sys.argv[1]
        print(f"Deploying branch: {branch}")
        push_to_all_remotes(branch)
    else:
        push_to_all_remotes()

if __name__ == "__main__":
    main()

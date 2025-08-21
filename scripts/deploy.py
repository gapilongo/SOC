"""
Deployment script for LG-SOTF.

This script handles the deployment of LG-SOTF to different environments.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def deploy_docker(environment: str):
    """Deploy using Docker."""
    print(f"🐳 Deploying to {environment} using Docker...")
    
    # Build Docker image
    print("Building Docker image...")
    subprocess.run([
        "docker", "build", "-t", f"lg-sotf:{environment}", "."
    ], check=True)
    
    # Run docker-compose
    print(f"Starting services with docker-compose...")
    subprocess.run([
        "docker-compose", "-f", f"docker/docker-compose.{environment}.yaml", "up", "-d"
    ], check=True)
    
    print(f"✅ Deployed to {environment} using Docker")


def deploy_kubernetes(environment: str):
    """Deploy using Kubernetes."""
    print(f"☸️  Deploying to {environment} using Kubernetes...")
    
    # Set kubectl context
    print("Setting kubectl context...")
    subprocess.run([
        "kubectl", "config", "use-context", f"{environment}-context"
    ], check=True)
    
    # Apply Kubernetes manifests
    print("Applying Kubernetes manifests...")
    subprocess.run([
        "kubectl", "apply", "-f", "k8s/"
    ], check=True)
    
    # Wait for deployment
    print("Waiting for deployment to be ready...")
    subprocess.run([
        "kubectl", "wait", "--for=condition=available", "deployment/lg-sotf", "--timeout=300s"
    ], check=True)
    
    print(f"✅ Deployed to {environment} using Kubernetes")


def run_health_checks(environment: str):
    """Run health checks after deployment."""
    print(f"🔍 Running health checks for {environment}...")
    
    # Get service URL
    result = subprocess.run([
        "kubectl", "get", "svc", "lg-sotf", "-o", "jsonpath='{.status.loadBalancer.ingress[0].hostname}'"
    ], capture_output=True, text=True)
    
    service_url = result.stdout.strip().strip("'")
    
    if not service_url:
        print("❌ Could not get service URL")
        return False
    
    # Run health check
    import requests
    try:
        response = requests.get(f"http://{service_url}/health", timeout=30)
        if response.status_code == 200:
            print("✅ Health check passed")
            return True
        else:
            print(f"❌ Health check failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Deploy LG-SOTF to different environments")
    parser.add_argument("environment", choices=["development", "testing", "staging", "production"],
                       help="Environment to deploy to")
    parser.add_argument("--method", choices=["docker", "kubernetes"], default="kubernetes",
                       help="Deployment method")
    parser.add_argument("--skip-health-checks", action="store_true",
                       help="Skip post-deployment health checks")
    
    args = parser.parse_args()
    
    try:
        if args.method == "docker":
            deploy_docker(args.environment)
        else:
            deploy_kubernetes(args.environment)
        
        if not args.skip_health_checks:
            if not run_health_checks(args.environment):
                print("❌ Health checks failed")
                sys.exit(1)
        
        print(f"🎉 Successfully deployed to {args.environment}!")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Deployment failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
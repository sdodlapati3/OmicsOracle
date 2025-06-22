#!/bin/bash

# Deploy OmicsOracle to all GitHub remotes using GitHub CLI for authentication
# Usage: ./deploy_to_all_remotes.sh [branch_name]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to get GitHub account for remote
get_account_for_remote() {
    case $1 in
        "origin") echo "sdodlapati3" ;;
        "sanjeeva") echo "SanjeevaRDodlapati" ;;
        "backup") echo "sdodlapa" ;;
        *) echo "" ;;
    esac
}

# Get current branch if not specified
BRANCH=${1:-$(git rev-parse --abbrev-ref HEAD)}

echo -e "${BLUE}🚀 Deploying OmicsOracle to all GitHub repositories...${NC}"
echo -e "${BLUE}🌿 Branch: $BRANCH${NC}"

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}⚠️  Warning: You have uncommitted changes${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled"
        exit 1
    fi
fi

# Get all remotes
REMOTES=$(git remote)

if [ -z "$REMOTES" ]; then
    echo -e "${RED}❌ No git remotes configured${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Configured remotes: $(echo $REMOTES | tr '\n' ' ')${NC}"
echo

# Push to each remote
SUCCESS_COUNT=0
TOTAL_COUNT=0

for REMOTE in $REMOTES; do
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    ACCOUNT=$(get_account_for_remote "$REMOTE")
    
    echo -e "${BLUE}📤 Pushing to remote '$REMOTE' (GitHub account: $ACCOUNT)...${NC}"
    
    # Switch to the appropriate GitHub account
    if [ -n "$ACCOUNT" ]; then
        echo -e "${YELLOW}🔄 Switching to GitHub account: $ACCOUNT${NC}"
        if gh auth switch --user "$ACCOUNT"; then
            echo -e "${GREEN}✅ Switched to $ACCOUNT${NC}"
        else
            echo -e "${RED}❌ Failed to switch to $ACCOUNT${NC}"
            continue
        fi
    fi
    
    # Push using git (will use the current authentication context)
    if git push "$REMOTE" "$BRANCH" 2>/dev/null; then
        echo -e "${GREEN}✅ Successfully pushed to $REMOTE${NC}"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo -e "${YELLOW}⚠️  Git push failed, trying with GitHub CLI...${NC}"
        # Alternative: Use gh to create/update the repository
        REPO_NAME="OmicsOracle"
        if gh repo view "$ACCOUNT/$REPO_NAME" >/dev/null 2>&1; then
            # Repository exists, just push
            if git push "$REMOTE" "$BRANCH" --force-with-lease; then
                echo -e "${GREEN}✅ Successfully pushed to $REMOTE with force-with-lease${NC}"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                echo -e "${RED}❌ Failed to push to $REMOTE${NC}"
            fi
        else
            echo -e "${YELLOW}Repository doesn't exist, creating it...${NC}"
            if gh repo create "$REPO_NAME" --public --description "AI-powered GEO metadata summarization tool"; then
                echo -e "${GREEN}✅ Created repository $ACCOUNT/$REPO_NAME${NC}"
                if git push "$REMOTE" "$BRANCH"; then
                    echo -e "${GREEN}✅ Successfully pushed to new repository${NC}"
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    echo -e "${RED}❌ Failed to push to new repository${NC}"
                fi
            else
                echo -e "${RED}❌ Failed to create repository${NC}"
            fi
        fi
    fi
    echo
done

# Switch back to primary account
echo -e "${YELLOW}🔄 Switching back to primary account (sdodlapati3)...${NC}"
gh auth switch --user "sdodlapati3"

# Summary
echo -e "${BLUE}📊 Deployment Summary:${NC}"
echo "=================================================="

for REMOTE in $REMOTES; do
    URL=$(git remote get-url "$REMOTE")
    ACCOUNT=$(get_account_for_remote "$REMOTE")
    echo -e "${REMOTE} (${ACCOUNT}): ${URL}"
done

echo "=================================================="
echo -e "Total: ${SUCCESS_COUNT}/${TOTAL_COUNT} repositories updated successfully"

if [ $SUCCESS_COUNT -eq $TOTAL_COUNT ]; then
    echo -e "${GREEN}🎉 All repositories updated successfully!${NC}"
    echo -e "${BLUE}🔗 Repository URLs:${NC}"
    echo -e "  • origin: https://github.com/sdodlapati3/OmicsOracle"
    echo -e "  • sanjeeva: https://github.com/SanjeevaRDodlapati/OmicsOracle"
    echo -e "  • backup: https://github.com/sdodlapa/OmicsOracle"
else
    echo -e "${YELLOW}⚠️  Some deployments failed. Check the output above for details.${NC}"
    exit 1
fi

#!/bin/bash

# Interactive Git Push Script
# This script automates the process of creating a new branch, committing changes, and pushing to GitHub

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Interactive Git Push Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Change to git repository root
# Find the .git directory by going up from the script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

# Navigate up until we find .git directory
while [ "$REPO_ROOT" != "/" ] && [ ! -d "$REPO_ROOT/.git" ]; do
    REPO_ROOT="$(dirname "$REPO_ROOT")"
done

if [ ! -d "$REPO_ROOT/.git" ]; then
    echo -e "${RED}Error: Not in a git repository!${NC}"
    exit 1
fi

# Change to repository root
cd "$REPO_ROOT" || {
    echo -e "${RED}Error: Failed to change to repository root: $REPO_ROOT${NC}"
    exit 1
}

echo -e "${GREEN}Working in repository: $REPO_ROOT${NC}"
echo ""

# Step 1: Check Current Git Status
echo -e "${YELLOW}Step 1: Checking current Git status...${NC}"
git status
echo ""

# Check if there are any changes to commit
if [ -z "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}No changes detected. Nothing to commit.${NC}"
    read -p "Do you still want to create a new branch? (y/n): " create_branch
    if [ "$create_branch" != "y" ] && [ "$create_branch" != "Y" ]; then
        echo -e "${RED}Exiting...${NC}"
        exit 0
    fi
fi

# Step 2: Get branch name from user
echo -e "${YELLOW}Step 2: Creating new branch${NC}"
read -p "Enter the new branch name: " branch_name

# Validate branch name
if [ -z "$branch_name" ]; then
    echo -e "${RED}Error: Branch name cannot be empty!${NC}"
    exit 1
fi

# Remove any spaces and special characters that might cause issues
branch_name=$(echo "$branch_name" | tr ' ' '-' | tr -cd '[:alnum:]-_')

echo -e "${GREEN}Using branch name: ${branch_name}${NC}"
echo ""

# Step 3: Create and switch to new branch
echo -e "${YELLOW}Step 3: Creating and switching to new branch '${branch_name}'...${NC}"
if git checkout -b "$branch_name"; then
    echo -e "${GREEN}✓ Successfully created and switched to branch '${branch_name}'${NC}"
else
    echo -e "${RED}Error: Failed to create branch. It may already exist.${NC}"
    read -p "Do you want to switch to existing branch '${branch_name}'? (y/n): " switch_branch
    if [ "$switch_branch" = "y" ] || [ "$switch_branch" = "Y" ]; then
        git checkout "$branch_name"
    else
        echo -e "${RED}Exiting...${NC}"
        exit 1
    fi
fi
echo ""

# Step 4: Add all changes
echo -e "${YELLOW}Step 4: Staging all changes...${NC}"
if git add -A; then
    echo -e "${GREEN}✓ Successfully staged all changes${NC}"
    # Show what was staged
    echo -e "${BLUE}Staged changes:${NC}"
    git status --short
else
    echo -e "${RED}Error: Failed to stage changes${NC}"
    exit 1
fi
echo ""

# Step 5: Commit changes
echo -e "${YELLOW}Step 5: Committing changes...${NC}"

# Verify there are staged changes
if [ -z "$(git diff --cached --name-only)" ]; then
    echo -e "${YELLOW}Warning: No changes are staged for commit.${NC}"
    read -p "Do you want to continue anyway? (y/n): " continue_anyway
    if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
        echo -e "${RED}Commit cancelled.${NC}"
        exit 1
    fi
fi

read -p "Enter commit message (or press Enter to use branch name): " commit_message

if [ -z "$commit_message" ]; then
    commit_message="$branch_name"
fi

if git commit -m "$commit_message"; then
    echo -e "${GREEN}✓ Successfully committed changes with message: '${commit_message}'${NC}"
else
    echo -e "${RED}Error: Failed to commit changes${NC}"
    echo -e "${YELLOW}This might happen if there are no changes to commit.${NC}"
    exit 1
fi
echo ""

# Step 6: Push to GitHub
echo -e "${YELLOW}Step 6: Pushing to GitHub...${NC}"
read -p "Push branch '${branch_name}' to origin? (y/n): " confirm_push

if [ "$confirm_push" = "y" ] || [ "$confirm_push" = "Y" ]; then
    if git push origin "$branch_name"; then
        echo -e "${GREEN}✓ Successfully pushed branch '${branch_name}' to origin${NC}"
        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${GREEN}All done! Your branch has been pushed to GitHub.${NC}"
        echo -e "${BLUE}You can now create a Pull Request on GitHub.${NC}"
        echo -e "${BLUE}========================================${NC}"
    else
        echo -e "${RED}Error: Failed to push to GitHub${NC}"
        echo -e "${YELLOW}You may need to set upstream: git push -u origin ${branch_name}${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Push cancelled. Branch '${branch_name}' is ready but not pushed.${NC}"
    echo -e "${YELLOW}You can push it later with: git push origin ${branch_name}${NC}"
fi
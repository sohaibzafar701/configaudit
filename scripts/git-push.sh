#!/bin/bash

# Interactive Git Branch Creation and Push Script
# This script creates a new branch, switches to it, and pushes code to GitHub

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Git Branch Creation and Push Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Check Current Git Status
echo -e "${YELLOW}Step 1: Checking current Git status...${NC}"
git status
echo ""

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
        if git checkout "$branch_name"; then
            echo -e "${GREEN}✓ Successfully switched to branch '${branch_name}'${NC}"
        else
            echo -e "${RED}Error: Failed to switch to branch${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Exiting...${NC}"
        exit 1
    fi
fi
echo ""

# Step 4: Check if there are changes to commit
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}Step 4: Staging and committing changes...${NC}"
    
    # Add all changes
    if git add .; then
        echo -e "${GREEN}✓ Successfully staged all changes${NC}"
    else
        echo -e "${RED}Error: Failed to stage changes${NC}"
        exit 1
    fi
    
    # Commit changes
    read -p "Enter commit message (or press Enter to use branch name): " commit_message
    
    if [ -z "$commit_message" ]; then
        commit_message="$branch_name"
    fi
    
    if git commit -m "$commit_message"; then
        echo -e "${GREEN}✓ Successfully committed changes with message: '${commit_message}'${NC}"
    else
        echo -e "${RED}Error: Failed to commit changes${NC}"
        exit 1
    fi
    echo ""
else
    echo -e "${YELLOW}No changes to commit.${NC}"
    echo ""
fi

# Step 5: Push to GitHub
echo -e "${YELLOW}Step 5: Pushing to GitHub...${NC}"
read -p "Push branch '${branch_name}' to origin? (y/n): " confirm_push

if [ "$confirm_push" = "y" ] || [ "$confirm_push" = "Y" ]; then
    # Try to push, if it fails, try with -u flag to set upstream
    if git push -u origin "$branch_name"; then
        echo -e "${GREEN}✓ Successfully pushed branch '${branch_name}' to origin${NC}"
        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${GREEN}All done! Your branch has been pushed to GitHub.${NC}"
        echo -e "${BLUE}You can now create a Pull Request on GitHub.${NC}"
        echo -e "${BLUE}========================================${NC}"
    else
        echo -e "${RED}Error: Failed to push to GitHub${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Push cancelled. Branch '${branch_name}' is ready but not pushed.${NC}"
    echo -e "${YELLOW}You can push it later with: git push -u origin ${branch_name}${NC}"
fi

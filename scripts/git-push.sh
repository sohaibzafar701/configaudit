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
    # Check remote URL to determine authentication method
    remote_url=$(git remote get-url origin 2>/dev/null)
    
    # Try to push and capture output
    push_output=$(git push -u origin "$branch_name" 2>&1)
    push_exit_code=$?
    
    # Show the output
    echo "$push_output"
    
    if [ $push_exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ Successfully pushed branch '${branch_name}' to origin${NC}"
        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${GREEN}All done! Your branch has been pushed to GitHub.${NC}"
        echo -e "${BLUE}You can now create a Pull Request on GitHub.${NC}"
        echo -e "${BLUE}========================================${NC}"
    else
        # Check for authentication errors
        if echo "$push_output" | grep -qi "authentication failed\|invalid username or token\|password authentication is not supported"; then
            echo ""
            echo -e "${RED}Authentication Error: GitHub no longer supports password authentication.${NC}"
            echo ""
            echo -e "${YELLOW}You have two options:${NC}"
            echo ""
            echo -e "${BLUE}Option 1: Use Personal Access Token (PAT)${NC}"
            echo -e "  1. Go to: https://github.com/settings/tokens"
            echo -e "  2. Click 'Generate new token' -> 'Generate new token (classic)'"
            echo -e "  3. Give it a name and select 'repo' scope"
            echo -e "  4. Copy the token and use it as your password when prompted"
            echo -e "  5. Or configure it: git config credential.helper store"
            echo ""
            echo -e "${BLUE}Option 2: Switch to SSH (Recommended)${NC}"
            read -p "Do you want to switch to SSH authentication? (y/n): " switch_ssh
            if [ "$switch_ssh" = "y" ] || [ "$switch_ssh" = "Y" ]; then
                # Extract repo path from HTTPS URL
                if echo "$remote_url" | grep -q "^https://"; then
                    repo_path=$(echo "$remote_url" | sed 's|https://github.com/||' | sed 's|\.git$||')
                    ssh_url="git@github.com:${repo_path}.git"
                    echo -e "${YELLOW}Switching remote URL to SSH...${NC}"
                    if git remote set-url origin "$ssh_url"; then
                        echo -e "${GREEN}✓ Remote URL updated to: ${ssh_url}${NC}"
                        echo ""
                        echo -e "${YELLOW}Make sure you have SSH keys set up:${NC}"
                        echo -e "  - Check: ssh -T git@github.com"
                        echo -e "  - If not set up, see: https://docs.github.com/en/authentication/connecting-to-github-with-ssh"
                        echo ""
                        read -p "Try pushing again now? (y/n): " retry_push
                        if [ "$retry_push" = "y" ] || [ "$retry_push" = "Y" ]; then
                            if git push -u origin "$branch_name"; then
                                echo -e "${GREEN}✓ Successfully pushed branch '${branch_name}' to origin${NC}"
                                echo ""
                                echo -e "${BLUE}========================================${NC}"
                                echo -e "${GREEN}All done! Your branch has been pushed to GitHub.${NC}"
                                echo -e "${BLUE}You can now create a Pull Request on GitHub.${NC}"
                                echo -e "${BLUE}========================================${NC}"
                            else
                                echo -e "${RED}Still failed. Please check your SSH setup.${NC}"
                                exit 1
                            fi
                        fi
                    else
                        echo -e "${RED}Failed to update remote URL${NC}"
                        exit 1
                    fi
                fi
            else
                echo -e "${YELLOW}To push manually later, use one of these methods:${NC}"
                echo -e "  - With PAT: git push -u origin ${branch_name}"
                echo -e "  - Or switch to SSH first: git remote set-url origin git@github.com:sohaibzafar701/configaudit.git"
                exit 1
            fi
        else
            echo -e "${RED}Error: Failed to push to GitHub${NC}"
            echo -e "${YELLOW}Error details:${NC}"
            echo "$push_output"
            exit 1
        fi
    fi
else
    echo -e "${YELLOW}Push cancelled. Branch '${branch_name}' is ready but not pushed.${NC}"
    echo -e "${YELLOW}You can push it later with: git push -u origin ${branch_name}${NC}"
fi

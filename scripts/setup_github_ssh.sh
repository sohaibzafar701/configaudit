#!/bin/bash

# GitHub SSH Setup Helper Script
# This script helps you set up SSH authentication for your GitHub account

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  GitHub SSH Setup Helper${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if the SSH key exists
if [ ! -f ~/.ssh/id_ed25519_sohaib.pub ]; then
    echo -e "${RED}Error: SSH key not found!${NC}"
    echo -e "${YELLOW}Please run the setup first.${NC}"
    exit 1
fi

echo -e "${YELLOW}Your SSH Public Key for sohaibzafar701:${NC}"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
cat ~/.ssh/id_ed25519_sohaib.pub
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}Instructions:${NC}"
echo "1. Copy the key above (the entire line)"
echo "2. Go to: ${BLUE}https://github.com/settings/keys${NC}"
echo "3. Click 'New SSH key'"
echo "4. Give it a title (e.g., 'ConfigAudit Server')"
echo "5. Paste the key and click 'Add SSH key'"
echo ""

read -p "Have you added the key to GitHub? (y/n): " key_added

if [ "$key_added" = "y" ] || [ "$key_added" = "Y" ]; then
    echo ""
    echo -e "${YELLOW}Testing SSH connection to GitHub...${NC}"
    echo ""
    
    if ssh -T git@github.com 2>&1 | grep -q "sohaibzafar701"; then
        echo -e "${GREEN}✓ Successfully authenticated as sohaibzafar701!${NC}"
        echo -e "${GREEN}✓ You can now push to your repositories.${NC}"
    else
        result=$(ssh -T git@github.com 2>&1)
        echo "$result"
        if echo "$result" | grep -q "Permission denied"; then
            echo ""
            echo -e "${RED}Authentication failed.${NC}"
            echo -e "${YELLOW}Please make sure:${NC}"
            echo "  - You've added the correct SSH key to GitHub"
            echo "  - The key was added to the sohaibzafar701 account"
            echo "  - You've saved the key on GitHub"
        fi
    fi
else
    echo -e "${YELLOW}Please add the key to GitHub first, then run this script again.${NC}"
fi

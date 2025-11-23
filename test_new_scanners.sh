#!/bin/bash
# Test script for new bug bounty scanners

echo "╔═══════════════════════════════════════════════╗"
echo "║   Testing New Bug Bounty Scanners            ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test target
TARGET="elsiddik.net"

echo -e "${CYAN}Target: $TARGET${NC}"
echo ""

# Test 1: IDOR Scanner
echo -e "${GREEN}[1/3] Testing IDOR Scanner...${NC}"
python scanners/idor_scanner.py -u "https://$TARGET" -o results
echo ""

# Test 2: SSRF Scanner
echo -e "${GREEN}[2/3] Testing SSRF Scanner...${NC}"
python scanners/ssrf_scanner.py -u "https://$TARGET" -o results
echo ""

# Test 3: Blind XSS Scanner (with short wait time for demo)
echo -e "${GREEN}[3/3] Testing Blind XSS Scanner...${NC}"
echo -e "${YELLOW}Note: Using short wait time for demo (30s)${NC}"
python scanners/blind_xss_scanner.py \
  -u "https://$TARGET" \
  --start-server \
  -p 8080 \
  -w 30 \
  -o results
echo ""

echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   All Scanner Tests Complete!                 ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Check the 'results/' directory for detailed reports${NC}"
echo ""
echo -e "${YELLOW}Pro Tip: For real bug bounty hunting:${NC}"
echo "  - Use 2+ test accounts for IDOR testing"
echo "  - Keep callback server running for days"
echo "  - Test on targets you have permission for"

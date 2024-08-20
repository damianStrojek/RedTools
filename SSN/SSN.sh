#!/bin/bash
#
# Scan Scope with Nmap (SSN)
# Copyright (C) 2024 Damian Strojek
#

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
ITALIC='\033[3m'
BOLD='\033[1m'
NC='\033[0m'

# Files containing the list of IPs
TARGETS_FILE="scope.txt"
SMB_TARGETS_FILE="scope-smb.txt"

# Output files
TCP_OPEN_PORTS="nmap-tcp-open-ports.txt"
UDP_OPEN_PORTS="nmap-udp-open-ports.txt"
TCP_OUTPUT_FILE="nmap-tcp-scan-results.txt"
UDP_OUTPUT_FILE="nmap-udp-scan-results.txt"
SMB_OUTPUT_FILE="smb-scan-results.txt"

# Function to show usage
usage() {
    echo -e "${YELLOW}Usage: sudo $0 {tcp|udp|smb}${NC}"
    echo -e "${YELLOW}  tcp  - Run a TCP scan and perform detailed service version checks${NC}"
    echo -e "${YELLOW}  udp  - Run a UDP scan and save only the information about open UDP ports${NC}"
    echo -e "${YELLOW}  smb  - Run SMB enumeration using enum4linux and crackmapexec on targets in scope-smb.txt${NC}"
    exit 1
}

# Ensure an argument is provided
if [ -z "$1" ]; then
    usage
fi

# Function to print detailed and colorized scan results for TCP/UDP
print_scan_results() {
    local IP="$1"

    # Extract and print the relevant information (ports, services, versions)
    if [ -z "$(echo "$SCAN_OUTPUT" | awk '/^PORT/ {flag=1; next} /^--/ {flag=0} flag && /tcp/')" ]; then
        echo -e "\n${RED}No results found for ${YELLOW}$IP${RED}.${NC}\n"
    else
        
        echo -e "${MAGENTA}Detailed results for ${YELLOW}${BOLD}$IP${MAGENTA}:${NC}\n"
        echo "$SCAN_OUTPUT" | awk '/^PORT/ {flag=1; next} /^--/ {flag=0} flag && /tcp/ {print "\t\033[3m" $0 "\033[0m"}'
        echo -e ''
    fi
}

# Clear the output files at the start
> "$TCP_OPEN_PORTS"
> "$UDP_OPEN_PORTS"
> "$TCP_OUTPUT_FILE"
> "$TCP_OUTPUT_FILE"
> "$UDP_OUTPUT_FILE"
> "$SMB_OUTPUT_FILE"

if [ "$1" == "tcp" ]; then
    echo -e "\n${BLUE}Starting TCP scan on ${YELLOW}${BOLD}$TARGETS_FILE${BLUE}.${NC}\n"
    
    # Perform TCP scan on the list of IPs
    sudo nmap -iL "$TARGETS_FILE" -sS --min-rate 5000 -p- -Pn --max-retries 1 -oG - | grep '/open/tcp/' > "$TCP_OPEN_PORTS"

    # Loop through each line of the grep output to parse IPs and ports
    while IFS= read -r line; do
        IP=$(echo "$line" | awk '{print $2}')
        PORTS=$(echo "$line" | grep -oP '\d+/open/tcp' | awk -F'/' '{print $1}' | paste -sd ',' -)

        if [ -n "$PORTS" ]; then
            echo -e "${GREEN}Open TCP ports on ${YELLOW}${BOLD}$IP${GREEN}: $PORTS${NC}"

            # Check if port 445 is open and add IP to SMB_TARGETS_FILE
            if [ "$(echo "$PORTS" | grep '445')" ]; then
                echo "$IP" >> "$SMB_TARGETS_FILE"
                echo -e "${GREEN}Port 445 is open on ${YELLOW}${BOLD}$IP${GREEN}. Added to $SMB_TARGETS_FILE${GREEN}.${NC}"
            fi

            echo -e "${MAGENTA}Performing detailed scan on ${YELLOW}${BOLD}$IP${MAGENTA}...${NC}"
            
            # Perform a detailed service version scan on the open ports
            SCAN_OUTPUT=$(sudo nmap -sTV -O -Pn -p "$PORTS" "$IP")

            print_scan_results $IP
            
            # Save full scan output to the final file
            echo "$SCAN_OUTPUT" >> "$TCP_OUTPUT_FILE"
            echo -e "\n-------------------------------\n" >> "$TCP_OUTPUT_FILE"
        else
            echo -e "${RED}No open TCP ports found on ${YELLOW}${BOLD}$IP${NC}"
        fi
    done < "$TCP_OPEN_PORTS"

    echo -e "${GREEN}${BOLD}TCP scan complete. Results saved in ${YELLOW}${BOLD}$TCP_OUTPUT_FILE${GREEN}${BOLD}.${NC}"

elif [ "$1" == "udp" ]; then
    echo -e "\n${BLUE}Starting UDP scan on ${YELLOW}${BOLD}$TARGETS_FILE${BLUE}.${NC}\n"

    # Perform UDP scan on the list of IPs
    while IFS= read -r ip; do
        
        echo -e "${MAGENTA}Performing UDP scan on ${YELLOW}${BOLD}$ip${MAGENTA}...${NC}"
        
        # Perform the UDP scan and capture the output
        SCAN_OUTPUT=$(sudo nmap -sU --min-rate 5000 --top-ports 1000 -Pn "$ip")
        
        print_scan_results $ip
        
        # Save full scan output to the final file
        echo "$SCAN_OUTPUT" >> "$UDP_OUTPUT_FILE"
        echo -e "\n-------------------------------\n" >> "$UDP_OUTPUT_FILE"
    done < "$TARGETS_FILE"

    echo -e "${GREEN}${BOLD}UDP scan complete. Results saved in ${YELLOW}${BOLD}$UDP_OUTPUT_FILE${GREEN}${BOLD}.${NC}"

elif [ "$1" == "smb" ]; then
    echo -e "\n${BLUE}Starting SMB scan on ${YELLOW}${BOLD}$SMB_TARGETS_FILE${BLUE}.${NC}\n"

    # Loop through each IP in the smb targets file
    while IFS= read -r ip; do

        echo -e "${MAGENTA}Running enum4linux on ${YELLOW}${BOLD}${ip}${MAGENTA}...${NC}\n"
        SCAN_OUTPUT=$(enum4linux -a "$ip")
        echo "$SCAN_OUTPUT"
        echo "$SCAN_OUTPUT" >> "$SMB_OUTPUT_FILE"

        echo -e "${MAGENTA}Running crackmapexec on ${YELLOW}${BOLD}${ip}${MAGENTA}...${NC}\n"
        SCAN_OUTPUT=$(crackmapexec smb "$ip" -u '' -p '' --shares)
        echo "$SCAN_OUTPUT"
        echo "$SCAN_OUTPUT" >> "$SMB_OUTPUT_FILE"

        echo -e "${NC}--------------------------------------${NC}"
    done < "$SMB_TARGETS_FILE"

    echo -e "${GREEN}${BOLD}SMB scan complete. Results saved in ${YELLOW}${BOLD}$SMB_OUTPUT_FILE${GREEN}${BOLD}.${NC}"
else
    usage
fi

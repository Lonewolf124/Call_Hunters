#!/bin/bash

# CallTrace - VoIP Network Metadata Analysis Tool
# Version 3.0 - Fully Integrated Version with All Components

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global variables
SELECTED_INTERFACE=""
TEMP_DIR="/tmp/calltrace"
PCAP_FILE=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Virtual environment detection and setup
VENV_PATH=""
PYTHON_CMD="python3"

# Call metrics storage
declare -A CALL_DATA

# Create temp directory
mkdir -p "$TEMP_DIR"

# Function to detect and activate virtual environment
setup_python_env() {
    local venv_candidates=(
        "$SCRIPT_DIR/venv"
        "$SCRIPT_DIR/.venv" 
        "./venv"
        "./.venv"
        "$HOME/venv"
        "$PWD/venv"
        "$PWD/.venv"
    )
    
    # Check if we're already in a virtual environment
    if [[ -n "$VIRTUAL_ENV" ]]; then
        VENV_PATH="$VIRTUAL_ENV"
        PYTHON_CMD="$VIRTUAL_ENV/bin/python3"
        show_success "Using active virtual environment: $VIRTUAL_ENV"
        return 0
    fi
    
    # Look for virtual environment
    for venv_dir in "${venv_candidates[@]}"; do
        if [[ -d "$venv_dir" && -f "$venv_dir/bin/python3" ]]; then
            VENV_PATH="$venv_dir"
            PYTHON_CMD="$venv_dir/bin/python3"
            show_success "Found virtual environment: $venv_dir"
            
            # Test if required packages are available
            if "$PYTHON_CMD" -c "import pandas, numpy, matplotlib, scapy, pyshark, joblib, sklearn" 2>/dev/null; then
                show_success "All required packages found in virtual environment"
                return 0
            else
                show_warning "Virtual environment found but missing packages"
            fi
            break
        fi
    done
    
    # If no venv found, check system Python
    if [[ -z "$VENV_PATH" ]]; then
        show_warning "No virtual environment found, using system Python"
        if ! python3 -c "import pandas, numpy, matplotlib, scapy, pyshark, joblib, sklearn" 2>/dev/null; then
            show_error "Required packages not found in system Python"
            echo -e "${YELLOW}Solutions:${NC}"
            echo -e "  1. Activate your virtual environment: ${CYAN}source /path/to/your/venv/bin/activate${NC}"
            echo -e "  2. Install packages in system Python: ${CYAN}pip3 install pandas numpy matplotlib scapy pyshark joblib scikit-learn${NC}"
            echo -e "  3. Create a new virtual environment in this directory"
            echo
            read -p "Would you like to create a virtual environment now? (y/n): " create_venv
            if [[ "$create_venv" =~ ^[Yy]$ ]]; then
                create_virtual_environment
            fi
            return 1
        fi
    fi
    
    return 0
}

# Function to create virtual environment
create_virtual_environment() {
    local venv_dir="$SCRIPT_DIR/venv"
    
    show_status "Creating virtual environment..."
    if python3 -m venv "$venv_dir"; then
        show_success "Virtual environment created: $venv_dir"
        
        # Activate and install packages
        source "$venv_dir/bin/activate"
        show_status "Installing required packages..."
        
        pip install --upgrade pip
        pip install pandas numpy matplotlib scapy pyshark joblib scikit-learn
        
        if [[ $? -eq 0 ]]; then
            show_success "All packages installed successfully"
            VENV_PATH="$venv_dir"
            PYTHON_CMD="$venv_dir/bin/python3"
            return 0
        else
            show_error "Failed to install packages"
            return 1
        fi
    else
        show_error "Failed to create virtual environment"
        return 1
    fi
}

# ASCII art for the tool
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "   ____________________________________________________________________"
    echo "  /                                                                   /"
    echo " /    ██████╗ █████╗ ██╗     ██╗     ████████╗██████╗  █████╗  ██████╗███████╗ /"
    echo "/    ██╔════╝██╔══██╗██║     ██║     ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝/"
    echo "\\    ██║     ███████║██║     ██║        ██║   ███████║███████║██║     █████╗  \\"
    echo " \\   ██║     ██╔══██║██║     ██║        ██║   ██╔══██║██╔══██║██║     ██╔══╝   \\"
    echo "  \\  ╚██████╗██║  ██║███████╗███████╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗  \\"
    echo "   \\  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝   \\"
    echo "    \\_\\"
    echo -e "${NC}"
    echo -e "${YELLOW}                     VoIP Call Tracing Through Network Metadata${NC}"
    echo -e "${BLUE}                           Version 3.0 | Complete Integration${NC}"
    
    # Show Python environment info
    if [[ -n "$VENV_PATH" ]]; then
        echo -e "${GREEN}                        Using Virtual Environment: $(basename "$VENV_PATH")${NC}"
    else
        echo -e "${YELLOW}                             Using System Python${NC}"
    fi
    echo
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check Python3
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check required Python files
    local python_files=("voip_tracer1.py" "voip_grapher.py" "voip_predictor1.py" "shubrat1.py")
    for file in "${python_files[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            missing_deps+=("$file")
        fi
    done
    
    # Check Python packages using the correct Python command
    if ! "$PYTHON_CMD" -c "import pandas, numpy, matplotlib, scapy, pyshark, joblib" 2>/dev/null; then
        echo -e "${YELLOW}[!] Some Python packages are missing. Checking individual packages...${NC}"
        
        local required_packages=("pandas" "numpy" "matplotlib" "scapy" "pyshark" "joblib" "sklearn")
        local missing_packages=()
        
        for package in "${required_packages[@]}"; do
            if ! "$PYTHON_CMD" -c "import $package" 2>/dev/null; then
                missing_packages+=("$package")
            fi
        done
        
        if [[ ${#missing_packages[@]} -gt 0 ]]; then
            echo -e "${RED}Missing packages: ${missing_packages[*]}${NC}"
            echo -e "${CYAN}Install with:${NC}"
            if [[ -n "$VENV_PATH" ]]; then
                echo -e "    ${CYAN}source $VENV_PATH/bin/activate${NC}"
                echo -e "    ${CYAN}pip install ${missing_packages[*]}${NC}"
            else
                echo -e "    ${CYAN}pip3 install ${missing_packages[*]}${NC}"
            fi
            sleep 3
        fi
    fi
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${RED}[-] Missing dependencies:${NC}"
        for dep in "${missing_deps[@]}"; do
            echo -e "    - $dep"
        done
        echo -e "${YELLOW}[!] Please ensure all files are in the same directory${NC}"
        return 1
    fi
    
    return 0
}

# Function to analyze PCAP file using voip_tracer1.py
analyze_pcap_metadata() {
    local pcap_file=$1
    
    if [ ! -f "$pcap_file" ]; then
        show_error "PCAP file not found: $pcap_file"
        return 1
    fi
    
    show_status "Analyzing PCAP file for VoIP metadata..."
    
    # Run voip_tracer1.py to extract metadata
    local output_csv="$TEMP_DIR/voip_analysis_$(date +%Y%m%d_%H%M%S).csv"
    
    if "$PYTHON_CMD" "$SCRIPT_DIR/voip_tracer1.py" "$pcap_file" -o "$output_csv" -v; then
        show_success "Metadata extraction completed"
        echo -e "${CYAN}Results saved to: $output_csv${NC}"
        
        # Load extracted data into CALL_DATA
        load_call_data_from_csv "$output_csv"
        return 0
    else
        show_error "Failed to analyze PCAP file"
        return 1
    fi
}

# Function to load call data from CSV
load_call_data_from_csv() {
    local csv_file=$1
    
    if [ ! -f "$csv_file" ]; then
        return 1
    fi
    
    # Read the first data row (assuming header exists)
    local data_line=$(sed -n '2p' "$csv_file")
    
    if [ -n "$data_line" ]; then
        # Parse CSV data (basic parsing)
        IFS=',' read -ra FIELDS <<< "$data_line"
        
        # Map fields based on expected CSV structure from voip_tracer1.py
        CALL_DATA[call_id]="${FIELDS[0]}"
        CALL_DATA[call_duration]="${FIELDS[1]}"
        CALL_DATA[caller_ip]="${FIELDS[2]}"
        CALL_DATA[callee_ip]="${FIELDS[3]}"
        CALL_DATA[start_time]="${FIELDS[4]}"
        CALL_DATA[end_time]="${FIELDS[5]}"
        CALL_DATA[avg_jitter]="${FIELDS[6]}"
        CALL_DATA[packet_loss_percent]="${FIELDS[7]}"
        CALL_DATA[codec_type]="${FIELDS[8]}"
        CALL_DATA[setup_time]="${FIELDS[9]}"
        CALL_DATA[packets_per_second]="${FIELDS[10]}"
        CALL_DATA[bytes_per_second]="${FIELDS[11]}"
        CALL_DATA[retransmission_count]="${FIELDS[12]}"
        CALL_DATA[response_code_variety]="${FIELDS[13]}"
        CALL_DATA[concurrent_calls]="${FIELDS[14]}"
        CALL_DATA[jitter_variance]="${FIELDS[15]}"
        CALL_DATA[port_range_used]="${FIELDS[16]}"
        CALL_DATA[call_termination_method]="${FIELDS[17]}"
        CALL_DATA[peak_bandwidth]="${FIELDS[18]}"
        CALL_DATA[talk_silence_ratio]="${FIELDS[19]}"
        
        show_success "Call data loaded successfully"
    fi
}

# Function to display metadata
display_metadata() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                         ${WHITE}VoIP CALL METADATA DISPLAY${GREEN}                          ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════╣${NC}"
    
    if [ ${#CALL_DATA[@]} -eq 0 ]; then
        echo -e "${GREEN}║${NC}                        ${RED}No call data available${NC}                            ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}                   ${YELLOW}Please analyze a PCAP file first${NC}                       ${GREEN}║${NC}"
    else
        printf "${GREEN}║${NC} ${CYAN}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Call ID:" "${CALL_DATA[call_id]}"
        printf "${GREEN}║${NC} ${CYAN}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Duration:" "${CALL_DATA[call_duration]} seconds"
        printf "${GREEN}║${NC} ${CYAN}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Caller IP:" "${CALL_DATA[caller_ip]}"
        printf "${GREEN}║${NC} ${CYAN}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Callee IP:" "${CALL_DATA[callee_ip]}"
        printf "${GREEN}║${NC} ${CYAN}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Start Time:" "${CALL_DATA[start_time]}"
        printf "${GREEN}║${NC} ${CYAN}%-20s${NC} %-50s ${GREEN}║${NC}\n" "End Time:" "${CALL_DATA[end_time]}"
        echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════╣${NC}"
        printf "${GREEN}║${NC} ${YELLOW}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Average Jitter:" "${CALL_DATA[avg_jitter]} ms"
        printf "${GREEN}║${NC} ${YELLOW}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Packet Loss:" "${CALL_DATA[packet_loss_percent]}%"
        printf "${GREEN}║${NC} ${YELLOW}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Codec Type:" "${CALL_DATA[codec_type]}"
        printf "${GREEN}║${NC} ${YELLOW}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Setup Time:" "${CALL_DATA[setup_time]} ms"
        printf "${GREEN}║${NC} ${YELLOW}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Packets/Second:" "${CALL_DATA[packets_per_second]}"
        printf "${GREEN}║${NC} ${YELLOW}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Bytes/Second:" "${CALL_DATA[bytes_per_second]}"
        echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════╣${NC}"
        printf "${GREEN}║${NC} ${MAGENTA}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Retransmissions:" "${CALL_DATA[retransmission_count]}"
        printf "${GREEN}║${NC} ${MAGENTA}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Response Codes:" "${CALL_DATA[response_code_variety]}"
        printf "${GREEN}║${NC} ${MAGENTA}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Concurrent Calls:" "${CALL_DATA[concurrent_calls]}"
        printf "${GREEN}║${NC} ${MAGENTA}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Port Range Used:" "${CALL_DATA[port_range_used]}"
        printf "${GREEN}║${NC} ${MAGENTA}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Peak Bandwidth:" "${CALL_DATA[peak_bandwidth]} bytes/s"
        printf "${GREEN}║${NC} ${MAGENTA}%-20s${NC} %-50s ${GREEN}║${NC}\n" "Talk/Silence:" "${CALL_DATA[talk_silence_ratio]}%"
    fi
    
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo
    echo -e "${CYAN}Press Enter to return to analysis menu...${NC}"
    read -r
}

# Function to run visualization
run_visualization() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        ${WHITE}METADATA VISUALIZATION${GREEN}                             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    if [ -z "$PCAP_FILE" ]; then
        show_error "No PCAP file loaded. Please analyze a PCAP file first."
        sleep 3
        return 1
    fi
    
    show_status "Launching VoIP Grapher visualization..."
    
    # Run voip_grapher.py using the correct Python command
    if "$PYTHON_CMD" "$SCRIPT_DIR/voip_grapher.py" "$PCAP_FILE"; then
        show_success "Visualization completed"
    else
        show_error "Visualization failed"
    fi
    
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Function to run anomaly detection
run_anomaly_detection() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        ${WHITE}ANOMALY DETECTION${GREEN}                                  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Check if we have CSV data from previous analysis
    local latest_csv=$(ls -t "$TEMP_DIR"/voip_analysis_*.csv 2>/dev/null | head -1)
    
    if [ -z "$latest_csv" ]; then
        show_error "No analysis data found. Please run PCAP analysis first."
        sleep 3
        return 1
    fi
    
    show_status "Running anomaly detection on call data..."
    
    # Run voip_predictor1.py using the correct Python command
    local output_file="$TEMP_DIR/anomaly_results_$(date +%Y%m%d_%H%M%S).csv"
    
    if "$PYTHON_CMD" "$SCRIPT_DIR/voip_predictor1.py" "$latest_csv" -o "$output_file" --summary; then
        show_success "Anomaly detection completed"
        echo -e "${CYAN}Results saved to: $output_file${NC}"
        
        # Display summary if results exist
        if [ -f "$output_file" ]; then
            echo
            echo -e "${YELLOW}Quick Summary:${NC}"
            local total_records=$(tail -n +2 "$output_file" | wc -l)
            local anomalies=$(tail -n +2 "$output_file" | cut -d',' -f-1 | grep -c "True" 2>/dev/null || echo "0")
            echo -e "  Total Records: $total_records"
            echo -e "  Anomalies Found: $anomalies"
            
            if [ "$anomalies" -gt 0 ]; then
                echo -e "${RED}⚠️ Anomalous behavior detected in VoIP traffic!${NC}"
            else
                echo -e "${GREEN}✅ No anomalies detected - traffic appears normal${NC}"
            fi
        fi
    else
        show_error "Anomaly detection failed"
    fi
    
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Function to run blacklist IP check
run_blacklist_check() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        ${WHITE}BLACKLIST IP SCANNER${GREEN}                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    if [ -z "$PCAP_FILE" ]; then
        show_error "No PCAP file loaded. Please analyze a PCAP file first."
        sleep 3
        return 1
    fi
    
    # Check if blacklist file exists
    local blacklist_file="$SCRIPT_DIR/Blacklisted ip.csv"
    if [ ! -f "$blacklist_file" ]; then
        show_warning "Blacklist file 'Blacklisted ip.csv' not found in current directory"
        echo -e "${CYAN}Enter path to blacklist CSV file: ${NC}"
        read -r blacklist_file
        
        if [ ! -f "$blacklist_file" ]; then
            show_error "Blacklist file not found: $blacklist_file"
            sleep 3
            return 1
        fi
    fi
    
    show_status "Scanning for blacklisted IPs in VoIP traffic..."
    
    # Create a temporary modified version of shubrat1.py with correct file paths
    local temp_scanner="$TEMP_DIR/shubrat2.py"
    
    # Copy and modify shubrat1.py to use our PCAP file
    sed "s|call1.pcap|$PCAP_FILE|g; s|Blacklisted ip.csv|$blacklist_file|g" "$SCRIPT_DIR/shubrat1.py" > "$temp_scanner"
    
    # Run the blacklist scanner using the correct Python command
    if "$PYTHON_CMD" "$temp_scanner"; then
        show_success "Blacklist scan completed"
        
        # Check if results file was created
        if [ -f "security_scan_results.txt" ]; then
            echo
            echo -e "${YELLOW}Security Scan Results:${NC}"
            cat security_scan_results.txt
        fi
    else
        show_error "Blacklist scan failed"
    fi
    
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Function to show analysis menu
show_analysis_menu() {
    while true; do
        clear
        print_banner
        
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                         ${WHITE}PCAP ANALYSIS MENU${GREEN}                                ║${NC}"
        echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════╣${NC}"
        
        if [ -n "$PCAP_FILE" ]; then
            printf "${GREEN}║${NC} ${BLUE}Loaded PCAP:${NC} %-58s ${GREEN}║${NC}\n" "$(basename "$PCAP_FILE")"
            echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════════════════╣${NC}"
        fi
        
        echo -e "${GREEN}║${NC}   Select analysis option:                                              ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}                                                                       ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}   ${YELLOW}1.${NC} Display Metadata                                                ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}   ${YELLOW}2.${NC} Visualization of Metadata                                       ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}   ${YELLOW}3.${NC} Anomaly Detection                                               ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}   ${YELLOW}4.${NC} Export Analysis Results                                         ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}   ${RED}5.${NC} Return to Main Menu                                             ${GREEN}║${NC}"
        echo -e "${GREEN}║${NC}                                                                       ${GREEN}║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
        
        echo
        echo -e "${CYAN}Select option [1-5]: ${NC}"
        read -r analysis_choice
        
        case $analysis_choice in
            1)
                display_metadata
                ;;
            2)
                run_visualization
                ;;
            3)
                run_anomaly_detection
                ;;
            4)
                export_analysis_results
                ;;
            5)
                return
                ;;
            *)
                show_error "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Function to export analysis results
export_analysis_results() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        ${WHITE}EXPORT ANALYSIS RESULTS${GREEN}                             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    local export_dir="$TEMP_DIR/exports_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$export_dir"
    
    show_status "Exporting analysis results..."
    
    # Copy all analysis files to export directory
    local files_copied=0
    
    # Copy CSV analysis files
    for file in "$TEMP_DIR"/voip_analysis_*.csv; do
        if [ -f "$file" ]; then
            cp "$file" "$export_dir/"
            ((files_copied++))
        fi
    done
    
    # Copy anomaly detection results
    for file in "$TEMP_DIR"/anomaly_results_*.csv; do
        if [ -f "$file" ]; then
            cp "$file" "$export_dir/"
            ((files_copied++))
        fi
    done
    
    # Copy security scan results
    if [ -f "security_scan_results.txt" ]; then
        cp "security_scan_results.txt" "$export_dir/"
        ((files_copied++))
    fi
    
    # Copy any graph data
    for file in "$TEMP_DIR"/voip_4param_analysis_*.csv; do
        if [ -f "$file" ]; then
            cp "$file" "$export_dir/"
            ((files_copied++))
        fi
    done
    
    if [ $files_copied -gt 0 ]; then
        show_success "Exported $files_copied files to: $export_dir"
        echo -e "${CYAN}Files exported:${NC}"
        ls -la "$export_dir"
    else
        show_warning "No analysis results found to export"
    fi
    
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Function to display the main menu
show_main_menu() {
    echo -e "${GREEN}┌───────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│                     ${WHITE}MAIN MENU${GREEN}                             │${NC}"
    echo -e "${GREEN}├───────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${GREEN}│${NC}   Select an option:                                        ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}                                                           ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${YELLOW}1.${NC} Analyze PCAP File                                    ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${YELLOW}2.${NC} Blacklist IP Scanner                                 ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${YELLOW}3.${NC} Network Interface Tools                              ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${YELLOW}4.${NC} Export & Reports                                     ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${YELLOW}5.${NC} Tool Settings                                        ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${YELLOW}6.${NC} About & Help                                         ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}   ${RED}0.${NC} Exit CallTrace                                      ${GREEN}│${NC}"
    echo -e "${GREEN}│${NC}                                                           ${GREEN}│${NC}"
    if [ -n "$PCAP_FILE" ]; then
        echo -e "${GREEN}│${NC}   ${BLUE}Current PCAP:${NC} ${YELLOW}$(basename "$PCAP_FILE")${NC}                        ${GREEN}│${NC}"
    fi
    echo -e "${GREEN}└───────────────────────────────────────────────────────────────┘${NC}"
    echo
    echo -e "${CYAN}Select an option [0-6]: ${NC}"
}

# Function to handle PCAP file input and analysis
handle_pcap_analysis() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                         ${WHITE}PCAP FILE ANALYSIS${GREEN}                                 ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${CYAN}Enter path to PCAP file: ${NC}"
    read -r pcap_path
    
    # Handle different path formats
    if [[ "$pcap_path" =~ ^C: ]]; then
        # Windows path - convert to WSL format
        local wsl_path="/mnt/c/${pcap_path:3}"
        wsl_path="${wsl_path//\\//}"
        local local_pcap="./call1.pcap"
        
        if [ -f "$wsl_path" ]; then
            cp "$wsl_path" "$local_pcap"
            pcap_path="$local_pcap"
            show_success "Copied PCAP file from Windows path"
        else
            show_error "Windows file not found: $pcap_path"
            sleep 3
            return 1
        fi
    fi
    
    if [ ! -f "$pcap_path" ]; then
        show_error "PCAP file not found: $pcap_path"
        sleep 3
        return 1
    fi
    
    PCAP_FILE="$(realpath "$pcap_path")"
    show_success "PCAP file loaded: $(basename "$PCAP_FILE")"
    
    # Analyze the PCAP file
    if analyze_pcap_metadata "$PCAP_FILE"; then
        show_success "PCAP analysis completed successfully"
        
        # Show analysis menu
        show_analysis_menu
    else
        show_error "PCAP analysis failed"
        sleep 3
    fi
}

# Function to show network interface tools
show_interface_tools() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                        ${WHITE}NETWORK INTERFACE TOOLS${GREEN}                             ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    show_status "Available network interfaces:"
    echo
    
    if command -v ip &> /dev/null; then
        ip link show | grep '^[0-9]' | while read line; do
            local iface=$(echo "$line" | awk '{print $2}' | sed 's/://')
            local ip=$(ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1)
            echo -e "   ${YELLOW}◆${NC} $iface ${CYAN}($ip)${NC}"
        done
    else
        ifconfig -a | grep '^[a-zA-Z]' | awk '{print $1}' | while read iface; do
            echo -e "   ${YELLOW}◆${NC} $iface"
        done
    fi
    
    echo
    echo -e "${CYAN}Enter interface name to monitor (or press Enter to skip): ${NC}"
    read -r SELECTED_INTERFACE
    
    if [ -n "$SELECTED_INTERFACE" ]; then
        show_success "Interface selected: $SELECTED_INTERFACE"
    fi
    
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Function to show help and about
show_help() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                           ${WHITE}HELP & ABOUT${GREEN}                                     ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${CYAN}CallTrace v3.0 - VoIP Network Analysis Tool${NC}"
    echo
    echo -e "${YELLOW}Features:${NC}"
    echo -e "  • PCAP file analysis and metadata extraction"
    echo -e "  • Real-time visualization of VoIP parameters"
    echo -e "  • Anomaly detection using machine learning"
    echo -e "  • Blacklisted IP scanning and security alerts"
    echo -e "  • Comprehensive reporting and export functions"
    echo
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  1. Start with 'Analyze PCAP File' to load your VoIP capture"
    echo -e "  2. Use 'Display Metadata' to view call details"
    echo -e "  3. Run 'Visualization' to see graphical analysis"
    echo -e "  4. Check for 'Anomaly Detection' to find suspicious patterns"
    echo -e "  5. Use 'Blacklist Scanner' to check for known malicious IPs"
    echo
    echo -e "${YELLOW}Required Files:${NC}"
    echo -e "  • voip_tracer1.py - Metadata extraction engine"
    echo -e "  • voip_grapher.py - Visualization component"  
    echo -e "  • voip_predictor1.py - Anomaly detection module"
    echo -e "  • shubrat1.py - Blacklist scanning module"
    echo -e "  • Blacklisted ip.csv - IP blacklist database"
    echo
    echo -e "${YELLOW}Dependencies:${NC}"
    echo -e "  • Python 3.x with pandas, numpy, matplotlib, scapy, pyshark"
    echo -e "  • tcpdump (for packet analysis)"
    echo -e "  • Linux/Unix environment recommended"
    echo
    echo -e "${YELLOW}Virtual Environment:${NC}"
    if [[ -n "$VENV_PATH" ]]; then
        echo -e "  • Currently using: $VENV_PATH"
        echo -e "  • Python command: $PYTHON_CMD"
    else
        echo -e "  • Using system Python: $PYTHON_CMD"
        echo -e "  • Recommend creating venv for better package management"
    fi
    echo
    echo -e "${RED}Support:${NC}"
    echo -e "  Report issues or get help with the CallTrace tool"
    echo -e "  Ensure all Python modules are in the same directory"
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Utility functions
show_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

show_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

show_error() {
    echo -e "${RED}[-]${NC} $1"
}

show_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Function to show tool settings
show_settings() {
    clear
    print_banner
    
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                          ${WHITE}TOOL SETTINGS${GREEN}                                    ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${CYAN}Current Configuration:${NC}"
    echo -e "  Temp Directory: $TEMP_DIR"
    echo -e "  Script Directory: $SCRIPT_DIR"
    echo -e "  Selected Interface: ${SELECTED_INTERFACE:-None}"
    echo -e "  Current PCAP: ${PCAP_FILE:-None}"
    echo -e "  Python Environment: ${VENV_PATH:-System Python}"
    echo -e "  Python Command: $PYTHON_CMD"
    echo
    
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  1. Clear temporary files"
    echo -e "  2. Check dependencies"
    echo -e "  3. Reset interface selection"
    echo -e "  4. View log files"
    echo -e "  5. Create virtual environment"
    echo -e "  6. Test Python environment"
    echo -e "  7. Return to main menu"
    echo
    echo -e "${CYAN}Select option [1-7]: ${NC}"
    read -r settings_choice
    
    case $settings_choice in
        1)
            show_status "Clearing temporary files..."
            rm -rf "$TEMP_DIR"/*
            mkdir -p "$TEMP_DIR"
            show_success "Temporary files cleared"
            ;;
        2)
            show_status "Checking dependencies..."
            check_dependencies
            ;;
        3)
            SELECTED_INTERFACE=""
            show_success "Interface selection reset"
            ;;
        4)
            show_status "Available log files:"
            ls -la "$TEMP_DIR" 2>/dev/null || echo "No log files found"
            ;;
        5)
            create_virtual_environment
            ;;
        6)
            show_status "Testing Python environment..."
            echo -e "Python version: $("$PYTHON_CMD" --version)"
            echo -e "Python path: $PYTHON_CMD"
            echo -e "Testing package imports..."
            "$PYTHON_CMD" -c "
import sys
print(f'Python executable: {sys.executable}')
packages = ['pandas', 'numpy', 'matplotlib', 'scapy', 'pyshark', 'joblib', 'sklearn']
for pkg in packages:
    try:
        __import__(pkg)
        print(f'✓ {pkg}')
    except ImportError as e:
        print(f'✗ {pkg} - {e}')
"
            ;;
        7)
            return
            ;;
        *)
            show_error "Invalid option"
            ;;
    esac
    
    echo
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# Main program logic
main() {
    # Setup Python environment first
    if ! setup_python_env; then
        echo -e "${RED}Failed to setup Python environment. Please check your virtual environment or install required packages.${NC}"
        exit 1
    fi
    
    # Check dependencies
    if ! check_dependencies; then
        echo -e "${RED}Please install missing dependencies and try again.${NC}"
        exit 1
    fi
    
    print_banner
    sleep 2
    
    while true; do
        show_main_menu
        read -r choice
        
        case $choice in
            1)
                handle_pcap_analysis
                ;;
            2)
                run_blacklist_check
                ;;
            3)
                show_interface_tools
                ;;
            4)
                export_analysis_results
                ;;
            5)
                show_settings
                ;;
            6)
                show_help
                ;;
            0)
                echo
                echo -e "${MAGENTA}Thank you for using CallTrace!${NC}"
                echo -e "${CYAN}All analysis data saved in: $TEMP_DIR${NC}"
                echo -e "${CYAN}Goodbye!${NC}"
                echo
                exit 0
                ;;
            *)
                show_error "Invalid option. Please try again."
                sleep 2
                ;;
        esac
        
        # Return to main menu after operations
        if [[ $choice != 0 ]]; then
            print_banner
        fi
    done
}

# Check if running in a terminal with sufficient size
check_terminal_size() {
    local lines=$(tput lines 2>/dev/null || echo "24")
    local cols=$(tput cols 2>/dev/null || echo "80")
    
    if [ $lines -lt 24 ] || [ $cols -lt 80 ]; then
        echo -e "${RED}Error: Terminal size too small!${NC}"
        echo "Please resize your terminal to at least 80x24 characters."
        echo "Current size: ${cols}x${lines}"
        exit 1
    fi
}

# Initial checks
check_terminal_size

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    show_warning "For full functionality, it's recommended to run as root"
    sleep 2
fi

# Start the main program
main

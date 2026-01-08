#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${SCRIPT_DIR}/cache"
PATTERNS_FILE="${SCRIPT_DIR}/patterns.yaml"

URLHAUS_DOMAINS="https://urlhaus.abuse.ch/downloads/text/"
URLHAUS_RECENT="https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_RECENT="https://threatfox.abuse.ch/downloads/iocs/recent/"
FIREHOL_LEVEL1="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

mkdir -p "$CACHE_DIR"

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_dependencies() {
    log "Проверка зависимостей..."
    
    if ! command -v curl &> /dev/null; then
        log_error "curl не установлен. Установите: apt install curl"
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "python3 не установлен"
        exit 1
    fi
    
    log_success "Все зависимости установлены"
}

download_urlhaus_domains() {
    log "Скачивание malicious domains из URLhaus..."
    
    local output_file="${CACHE_DIR}/urlhaus_domains.txt"
    
    if curl -s --fail "$URLHAUS_DOMAINS" -o "$output_file" 2>/dev/null; then
        local count=$(grep -v "^#" "$output_file" | grep -v "^$" | wc -l)
        log_success "URLhaus: скачано ${count} записей"
    else
        log_warning "Не удалось скачать URLhaus domains"
        return 1
    fi
}

download_urlhaus_recent() {
    log "Скачивание recent URLs из URLhaus..."
    
    local output_file="${CACHE_DIR}/urlhaus_recent.csv"
    
    if curl -s --fail "$URLHAUS_RECENT" -o "$output_file" 2>/dev/null; then
        local count=$(wc -l < "$output_file")
        log_success "URLhaus recent: скачано ${count} записей"
    else
        log_warning "Не удалось скачать URLhaus recent"
        return 1
    fi
}

download_threatfox() {
    log "Скачивание IoC из ThreatFox..."
    
    local output_file="${CACHE_DIR}/threatfox_ioc.json"
    
    if curl -s --fail "$THREATFOX_RECENT" -o "$output_file" 2>/dev/null; then
        log_success "ThreatFox: данные скачаны"
    else
        log_warning "Не удалось скачать ThreatFox IoC"
        return 1
    fi
}

download_firehol() {
    log "Скачивание IP blocklist из Firehol..."
    
    local output_file="${CACHE_DIR}/firehol_ips.txt"
    
    if curl -s --fail "$FIREHOL_LEVEL1" -o "$output_file" 2>/dev/null; then
        local count=$(grep -v "^#" "$output_file" | grep -v "^$" | wc -l)
        log_success "Firehol: скачано ${count} IP/subnet"
    else
        log_warning "Не удалось скачать Firehol blocklist"
        return 1
    fi
}

extract_tlds() {
    log "Извлечение TLD из URLhaus данных..."
    
    local input_file="${CACHE_DIR}/urlhaus_domains.txt"
    local output_file="${CACHE_DIR}/extracted_tlds.txt"
    
    if [[ -f "$input_file" ]]; then
        grep -v "^#" "$input_file" | \
            grep -oE '\.[a-z]{2,}$' | \
            sort | uniq -c | sort -rn | \
            head -50 > "$output_file"
        
        log_success "Извлечено TLD: $(wc -l < "$output_file")"
    fi
}

show_stats() {
    log "=== Статистика кэша ==="
    
    echo ""
    for file in "${CACHE_DIR}"/*; do
        if [[ -f "$file" ]]; then
            local size=$(du -h "$file" | cut -f1)
            local lines=$(wc -l < "$file" 2>/dev/null || echo "N/A")
            local modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$file" 2>/dev/null || stat -c "%y" "$file" 2>/dev/null | cut -d' ' -f1,2)
            printf "  %-30s %8s  %10s lines  %s\n" "$(basename "$file")" "$size" "$lines" "$modified"
        fi
    done
    echo ""
}

update_patterns_yaml() {
    log "Обновление patterns.yaml..."
    
    if [[ -f "$PATTERNS_FILE" ]]; then
        local today=$(date '+%Y-%m-%d')
        
        cp "$PATTERNS_FILE" "${PATTERNS_FILE}.bak"
        
        log_warning "Автоматический merge пока не реализован"
        log "Скачанные данные находятся в: ${CACHE_DIR}/"
        log "Вы можете вручную добавить новые паттерны в patterns.yaml"
    fi
}

check_freshness() {
    log "Проверка актуальности кэша..."
    
    local now=$(date +%s)
    local max_age=$((24 * 60 * 60))
    
    for file in "${CACHE_DIR}"/*; do
        if [[ -f "$file" ]]; then
            local modified=$(stat -f "%m" "$file" 2>/dev/null || stat -c "%Y" "$file" 2>/dev/null)
            local age=$((now - modified))
            local name=$(basename "$file")
            
            if [[ $age -gt $max_age ]]; then
                log_warning "${name}: устарел ($(($age / 3600)) часов)"
            else
                log_success "${name}: актуален ($(($age / 3600)) часов)"
            fi
        fi
    done
}

show_help() {
    echo "TBMI Sandbox - Pattern Update Script"
    echo ""
    echo "Использование:"
    echo "  $0              Скачать все источники"
    echo "  $0 --domains    Только URLhaus domains"
    echo "  $0 --ioc        Только ThreatFox IoC"
    echo "  $0 --ips        Только Firehol IP blocklist"
    echo "  $0 --check      Проверить актуальность кэша"
    echo "  $0 --stats      Показать статистику"
    echo "  $0 --help       Эта справка"
    echo ""
    echo "Источники:"
    echo "  - abuse.ch URLhaus: malicious URLs и domains"
    echo "  - abuse.ch ThreatFox: IoC (Indicators of Compromise)"
    echo "  - Firehol: IP blocklists"
    echo ""
    echo "Кэш сохраняется в: ${CACHE_DIR}/"
}

main() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║  TBMI Sandbox - Pattern Updater        ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    case "${1:-all}" in
        --help|-h)
            show_help
            ;;
        --check)
            check_freshness
            ;;
        --stats)
            show_stats
            ;;
        --domains)
            check_dependencies
            download_urlhaus_domains
            extract_tlds
            ;;
        --ioc)
            check_dependencies
            download_threatfox
            ;;
        --ips)
            check_dependencies
            download_firehol
            ;;
        all|"")
            check_dependencies
            
            log "Скачивание всех источников..."
            echo ""
            
            download_urlhaus_domains || true
            download_urlhaus_recent || true
            download_threatfox || true
            download_firehol || true
            extract_tlds || true
            
            echo ""
            show_stats
            update_patterns_yaml
            
            echo ""
            log_success "Обновление завершено!"
            log "Кэш: ${CACHE_DIR}/"
            ;;
        *)
            log_error "Неизвестная опция: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"

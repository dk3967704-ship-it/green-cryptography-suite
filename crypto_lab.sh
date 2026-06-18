#!/bin/bash
# ============================================================
#  CRYPTO_LAB.sh  --  Cryptography Toolkit (Bash Edition)
#  Cyber-Security learning project
#  Educational use only -- DO NOT use for real security.
# ============================================================

# ---------- Colors (green / black hacker theme) ----------
G='\033[1;32m'      # bright green
DG='\033[0;32m'     # dim green
R='\033[1;31m'      # red (errors)
Y='\033[1;33m'      # yellow (warnings)
B='\033[1;30m'      # dark grey
W='\033[1;37m'      # bright white
N='\033[0m'         # reset
BG='\033[40m'       # black bg

# ---------- Helpers ----------
clear_screen() { printf '\033[2J\033[H'; }

banner() {
    clear_screen
    echo -e "${G}"
    cat <<'EOF'
   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗     ██╗      █████╗ ██████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗    ██║     ██╔══██╗██╔══██╗
  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║    ██║     ███████║██████╔╝
  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║    ██║     ██╔══██║██╔══██╗
  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝    ███████╗██║  ██║██████╔╝
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝     ╚══════╝╚═╝  ╚═╝╚═════╝
EOF
    echo -e "${DG}        >> CYBER-SECURITY // CRYPTOGRAPHY TOOLKIT // v1.0 <<${N}"
    echo -e "${B}        ============================================================${N}\n"
}

line() { echo -e "${DG}------------------------------------------------------------${N}"; }

pause() {
    echo ""
    echo -ne "${DG}[ press ENTER to continue ]${N}"
    read -r _
}

ok()    { echo -e "${G}[+] $*${N}"; }
info()  { echo -e "${DG}[*] $*${N}"; }
warn()  { echo -e "${Y}[!] $*${N}"; }
err()   { echo -e "${R}[x] $*${N}"; }

read_text() {
    local prompt="$1" var
    echo -ne "${G}${prompt} > ${N}"
    read -r var
    echo "$var"
}

# ============================================================
#  CIPHERS
# ============================================================

# ---------- Caesar ----------
caesar() {
    local text="$1" shift="$2" mode="$3" out="" c o b s=$shift
    [[ "$mode" == "d" ]] && s=$((26 - shift % 26))
    for ((i=0; i<${#text}; i++)); do
        c="${text:$i:1}"
        o=$(printf '%d' "'$c")
        if   (( o>=65 && o<=90 )); then b=65
        elif (( o>=97 && o<=122 )); then b=97
        else out+="$c"; continue; fi
        out+=$(printf "\\$(printf '%03o' $(( (o-b+s)%26 + b )))")
    done
    printf '%s' "$out"
}

# ---------- Atbash ----------
atbash() {
    echo "$1" | tr 'A-Za-z' 'Z-Aa-z' | tr 'A-Za-z' 'Z-Az-a'
}

# ---------- ROT13 ----------
rot13() { echo "$1" | tr 'A-Za-z' 'N-ZA-Mn-za-m'; }

# ---------- Vigenere ----------
vigenere() {
    local text="$1" key="$2" mode="$3" out="" c o b s ki=0 kc kch
    key=$(echo "$key" | tr -cd 'A-Za-z' | tr 'A-Z' 'a-z')
    [[ -z "$key" ]] && { echo "$text"; return; }
    for ((i=0; i<${#text}; i++)); do
        c="${text:$i:1}"
        o=$(printf '%d' "'$c")
        if   (( o>=65 && o<=90 )); then b=65
        elif (( o>=97 && o<=122 )); then b=97
        else out+="$c"; continue; fi
        kch="${key:$((ki % ${#key})):1}"
        kc=$(( $(printf '%d' "'$kch") - 97 ))
        [[ "$mode" == "d" ]] && kc=$(( (26 - kc) % 26 ))
        out+=$(printf "\\$(printf '%03o' $(( (o-b+kc)%26 + b )))")
        ki=$((ki+1))
    done
    printf '%s' "$out"
}

# ---------- XOR ----------
xor_cipher() {
    local text="$1" key="$2" out="" tb kb
    [[ -z "$key" ]] && { echo "$text"; return; }
    for ((i=0; i<${#text}; i++)); do
        tb=$(printf '%d' "'${text:$i:1}")
        kb=$(printf '%d' "'${key:$((i % ${#key})):1}")
        out+=$(printf '%02x' $((tb ^ kb)))
    done
    printf '%s' "$out"   # output as hex (safe to display)
}
xor_decipher() {
    local hex="$1" key="$2" out="" tb kb i=0 j=0
    [[ -z "$key" ]] && { echo "$hex"; return; }
    while (( i < ${#hex} )); do
        tb=$((16#${hex:$i:2}))
        kb=$(printf '%d' "'${key:$((j % ${#key})):1}")
        out+=$(printf "\\$(printf '%03o' $((tb ^ kb)))")
        i=$((i+2)); j=$((j+1))
    done
    printf '%s' "$out"
}

# ---------- Base64 ----------
b64_encode() { printf '%s' "$1" | base64; }
b64_decode() { printf '%s' "$1" | base64 -d 2>/dev/null || echo "[invalid base64]"; }

# ---------- Hex ----------
hex_encode() { printf '%s' "$1" | xxd -p | tr -d '\n'; }
hex_decode() { printf '%s' "$1" | tr -d ' \n' | xxd -r -p 2>/dev/null; }

# ---------- Binary ----------
bin_encode() {
    local text="$1" out=""
    for ((i=0; i<${#text}; i++)); do
        local o=$(printf '%d' "'${text:$i:1}")
        local b=""
        for ((j=7; j>=0; j--)); do b+=$(( (o>>j)&1 )); done
        out+="$b "
    done
    printf '%s' "$out"
}
bin_decode() {
    local out=""
    for word in $1; do
        out+=$(printf "\\$(printf '%03o' $((2#$word)))")
    done
    printf '%s' "$out"
}

# ---------- Hashes ----------
hash_md5()    { printf '%s' "$1" | md5sum    | awk '{print $1}'; }
hash_sha1()   { printf '%s' "$1" | sha1sum   | awk '{print $1}'; }
hash_sha256() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }
hash_sha512() { printf '%s' "$1" | sha512sum | awk '{print $1}'; }

# ---------- Random key ----------
gen_key() {
    local len="${1:-16}"
    tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c "$len"
    echo
}

# ============================================================
#  TOOL WRAPPERS  (handle UI for each cipher)
# ============================================================
show_result() {
    line
    echo -e "${DG}INPUT  >${N} $1"
    echo -e "${G}OUTPUT >${N} ${W}$2${N}"
    line
}

tool_caesar() {
    banner
    echo -e "${G}[ CAESAR CIPHER ]${N}\n"
    local txt=$(read_text "Text")
    local sh=$(read_text "Shift (1-25)")
    echo -ne "${G}Mode [e]ncrypt / [d]ecrypt > ${N}"; read -r m
    local out=$(caesar "$txt" "${sh:-3}" "${m:-e}")
    show_result "$txt" "$out"
    pause
}

tool_atbash() {
    banner; echo -e "${G}[ ATBASH CIPHER ]${N}\n"
    local txt=$(read_text "Text")
    show_result "$txt" "$(atbash "$txt")"
    pause
}

tool_rot13() {
    banner; echo -e "${G}[ ROT13 ]${N}\n"
    local txt=$(read_text "Text")
    show_result "$txt" "$(rot13 "$txt")"
    pause
}

tool_vigenere() {
    banner; echo -e "${G}[ VIGENERE CIPHER ]${N}\n"
    local txt=$(read_text "Text")
    local key=$(read_text "Key (letters)")
    echo -ne "${G}Mode [e]ncrypt / [d]ecrypt > ${N}"; read -r m
    show_result "$txt" "$(vigenere "$txt" "$key" "${m:-e}")"
    pause
}

tool_xor() {
    banner; echo -e "${G}[ XOR CIPHER ]${N}\n"
    echo -e "${DG}Encrypt: text + key -> hex${N}"
    echo -e "${DG}Decrypt: hex  + key -> text${N}\n"
    echo -ne "${G}Mode [e]ncrypt / [d]ecrypt > ${N}"; read -r m
    local key=$(read_text "Key")
    local txt=$(read_text "Input")
    local out
    if [[ "$m" == "d" ]]; then out=$(xor_decipher "$txt" "$key")
    else                        out=$(xor_cipher   "$txt" "$key"); fi
    show_result "$txt" "$out"
    pause
}

tool_base64() {
    banner; echo -e "${G}[ BASE64 ]${N}\n"
    echo -ne "${G}Mode [e]ncode / [d]ecode > ${N}"; read -r m
    local txt=$(read_text "Input")
    local out
    [[ "$m" == "d" ]] && out=$(b64_decode "$txt") || out=$(b64_encode "$txt")
    show_result "$txt" "$out"
    pause
}

tool_hex() {
    banner; echo -e "${G}[ HEX ]${N}\n"
    echo -ne "${G}Mode [e]ncode / [d]ecode > ${N}"; read -r m
    local txt=$(read_text "Input")
    local out
    [[ "$m" == "d" ]] && out=$(hex_decode "$txt") || out=$(hex_encode "$txt")
    show_result "$txt" "$out"
    pause
}

tool_binary() {
    banner; echo -e "${G}[ BINARY ]${N}\n"
    echo -ne "${G}Mode [e]ncode / [d]ecode > ${N}"; read -r m
    local txt=$(read_text "Input")
    local out
    [[ "$m" == "d" ]] && out=$(bin_decode "$txt") || out=$(bin_encode "$txt")
    show_result "$txt" "$out"
    pause
}

tool_hash() {
    banner; echo -e "${G}[ HASHING ]${N}\n"
    echo -e "${DG}  1) MD5      2) SHA-1${N}"
    echo -e "${DG}  3) SHA-256  4) SHA-512${N}"
    echo -ne "${G}Choose > ${N}"; read -r h
    local txt=$(read_text "Text")
    local out
    case "$h" in
        1) out=$(hash_md5    "$txt");;
        2) out=$(hash_sha1   "$txt"); warn "SHA-1 is cryptographically broken.";;
        3) out=$(hash_sha256 "$txt");;
        4) out=$(hash_sha512 "$txt");;
        *) err "invalid"; pause; return;;
    esac
    show_result "$txt" "$out"
    pause
}

tool_genkey() {
    banner; echo -e "${G}[ RANDOM KEY GENERATOR ]${N}\n"
    local len=$(read_text "Length (default 16)")
    [[ -z "$len" ]] && len=16
    local key=$(gen_key "$len")
    line
    echo -e "${G}KEY >${N} ${W}$key${N}"
    line
    pause
}

tool_freq() {
    banner; echo -e "${G}[ FREQUENCY ANALYSIS ]${N}\n"
    info "Useful for breaking Caesar/substitution ciphers."
    local txt=$(read_text "Ciphertext")
    line
    echo "$txt" | tr -cd 'A-Za-z' | tr 'A-Z' 'a-z' | fold -w1 | \
        sort | uniq -c | sort -rn | \
        awk -v G="\033[1;32m" -v N="\033[0m" \
            '{ bar=""; for(i=0;i<$1;i++) bar=bar"#"; printf "%s  %s  %3d  %s%s\n", G, $2, $1, bar, N }'
    line
    pause
}

tool_about() {
    banner
    echo -e "${G}[ ABOUT ]${N}\n"
    cat <<EOF
  ${DG}Project :${N} CryptoLab (Bash Edition)
  ${DG}Topic   :${N} Cryptography for Cyber-Security
  ${DG}Built   :${N} 100% pure Bash + coreutils (md5sum, sha*sum, base64, xxd)
  ${DG}Theme   :${N} Hacker terminal (green on black)

  ${G}Ciphers included:${N}
    - Caesar shift
    - Atbash (reverse alphabet)
    - ROT13
    - Vigenere (polyalphabetic, keyword-based)
    - XOR (with hex output)
    - Base64 encode/decode
    - Hex encode/decode
    - Binary encode/decode
    - Hashing (MD5, SHA-1, SHA-256, SHA-512)
    - Random key generator
    - Frequency analysis (for cryptanalysis)

  ${Y}DISCLAIMER:${N} Educational use only. Classical ciphers shown here
  are NOT secure and must NEVER be used to protect real data.
EOF
    pause
}

# ============================================================
#  MAIN MENU
# ============================================================
main_menu() {
    while true; do
        banner
        echo -e "${G}  ┌──────────────────────────────────────────┐${N}"
        echo -e "${G}  │           >> MAIN MENU <<                │${N}"
        echo -e "${G}  ├──────────────────────────────────────────┤${N}"
        echo -e "${G}  │  ${W}[1]${G}  Caesar Cipher                     │${N}"
        echo -e "${G}  │  ${W}[2]${G}  Atbash Cipher                     │${N}"
        echo -e "${G}  │  ${W}[3]${G}  ROT13                             │${N}"
        echo -e "${G}  │  ${W}[4]${G}  Vigenere Cipher                   │${N}"
        echo -e "${G}  │  ${W}[5]${G}  XOR Cipher                        │${N}"
        echo -e "${G}  │  ${W}[6]${G}  Base64 Encode / Decode            │${N}"
        echo -e "${G}  │  ${W}[7]${G}  Hex Encode / Decode               │${N}"
        echo -e "${G}  │  ${W}[8]${G}  Binary Encode / Decode            │${N}"
        echo -e "${G}  │  ${W}[9]${G}  Hashing (MD5/SHA-1/256/512)       │${N}"
        echo -e "${G}  │  ${W}[10]${G} Random Key Generator              │${N}"
        echo -e "${G}  │  ${W}[11]${G} Frequency Analysis (cryptanalysis)│${N}"
        echo -e "${G}  │  ${W}[12]${G} About                             │${N}"
        echo -e "${G}  │  ${W}[0]${G}  Exit                              │${N}"
        echo -e "${G}  └──────────────────────────────────────────┘${N}"
        echo ""
        echo -ne "${G}  root@cryptolab:~# ${N}"
        read -r choice
        case "$choice" in
            1)  tool_caesar   ;;
            2)  tool_atbash   ;;
            3)  tool_rot13    ;;
            4)  tool_vigenere ;;
            5)  tool_xor      ;;
            6)  tool_base64   ;;
            7)  tool_hex      ;;
            8)  tool_binary   ;;
            9)  tool_hash     ;;
            10) tool_genkey   ;;
            11) tool_freq     ;;
            12) tool_about    ;;
            0)  clear_screen
                echo -e "${G}[+] session terminated. stay safe out there.${N}\n"
                exit 0 ;;
            *)  err "invalid option"; sleep 1 ;;
        esac
    done
}

# ---------- Dependency check ----------
check_deps() {
    local missing=()
    for cmd in base64 xxd md5sum sha1sum sha256sum sha512sum tr awk; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        err "missing required commands: ${missing[*]}"
        echo "install coreutils + vim-common (for xxd) and try again."
        exit 1
    fi
}

# ---------- Boot ----------
check_deps
main_menu

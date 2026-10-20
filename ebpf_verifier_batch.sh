#!/usr/bin/env bash
# =============================================================================
# ebpf_verifier_batch.sh — eBPF/XDP Model Compatibility Verifier (v4)
# Referensi: https://www.kernel.org/doc/html/latest/bpf/verifier.html
#
# Method: model header + XDP stub -> clang -> `bpftool -d prog load` (kernel verifier)
# Program hanya di-LOAD (di-pin lalu dihapus), TIDAK di-attach ke NIC.
#
# Pemakaian (di folder yang berisi header .h + xdp_model_stub.c):
#   bash ebpf_verifier_batch.sh                       # semua model, -O2 lalu -O3 (default)
#   OPTS=-O2 bash ebpf_verifier_batch.sh              # hanya satu level  (OPT=-O2 juga diterima)
#   OPTS="-O2 -O3 -O1" bash ebpf_verifier_batch.sh    # daftar level bebas; dijalankan berurutan
#   RESUME=1 bash ebpf_verifier_batch.sh              # lanjutkan: lewati nama yang sudah ada di hasil
#   ONLY=MLP bash ebpf_verifier_batch.sh              # hanya MLP   (ONLY="DT RF MLP" = default)
#   FILTER='_a__|b-S1' bash ebpf_verifier_batch.sh    # hanya nama yang cocok regex (ERE)
#   JOBS=4 bash ebpf_verifier_batch.sh                # paralel (verifier 1 thread per proses)
#   TIMEOUT=600 ...                                   # batas detik per load (default 900)
#   PINDIR=/sys/fs/bpf/vt N_FEAT=9 ...                # override opsional
#
# Header yang dicari (case-insensitive, *_bpf.h diabaikan):
#   DT : Run*_DT*.h  DT_*.h  dt_*.h
#   RF : Run*_RF*.h  RF_*.h  rf_*.h
#   MLP: Run*_MLP*.h MLP_*.h mlp_*.h
# Nama fungsi *_predict (dan *_normalize untuk MLP) DIBACA dari isi header, bukan
# dari nama file (nama file seperti MLP_a__legacy-mlp-01 bukan identifier C yang sah).
#
# Hasil & log dipisah per level optimisasi (hasil dari level berbeda TIDAK boleh dicampur):
#   verifier_results_O2.txt  verifier_logs_O2/      verifier_results_O3.txt  verifier_logs_O3/
# Bila lebih dari satu level, di akhir dicetak perbandingan model yang statusnya berbeda
# antar level (mis. PASS di -O2 tapi gagal di -O3).
# PENTING: RESUME=1 hanya melanjutkan level yang sama (file hasil per level terpisah).
#
# Format baris hasil (kompatibel dengan metrics_tables.load_verifier_results):
#   <nama> : PASS : insn=<statis> processed=<verifier> states=<total_states>
#   <nama> : VERIFIER_FAIL : <kelas> processed=<N> why=<baris error terakhir>
#   <nama> : COMPILE_FAIL : <alasan>
# kelas: state-explosion | stack-limit | loop | pointer-arith | bounds-check | verifier-reject | timeout | unknown
#
# Catatan: log verifier (bpftool -d) bisa ratusan MB sampai GB untuk model besar dan ditulis ke $TMPDIR.
# Jika /tmp adalah tmpfs (RAM), arahkan ke disk:  TMPDIR=/path/disk/lega bash ebpf_verifier_batch.sh
#
# Setup:
#   sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
#   sed -i 's/\r//' ebpf_verifier_batch.sh   # kalau file berasal dari Windows (CRLF)
# =============================================================================

set -uo pipefail

SELF="$(realpath "$0")"
WORKDIR="$(dirname "$SELF")"
cd "$WORKDIR" || exit 1
STUB="$WORKDIR/xdp_model_stub.c"
PINDIR="${PINDIR:-/sys/fs/bpf/verifier_test}"

# ── Level optimisasi ───────────────────────────────────────────────────────────
# OPTS (atau OPT) = daftar level dipisah spasi. Default: -O2 lalu -O3.
OPTS="${OPTS:-${OPT:--O2 -O3}}"
tag_of() { printf '%s' "${1//[^A-Za-z0-9]/}"; }      # "-O2" -> "O2"
read -ra LEVELS <<< "$OPTS"
[ "${#LEVELS[@]}" -ge 1 ] || { echo "OPTS kosong"; exit 1; }

# Bandingkan hasil antar level: tampilkan model yang statusnya berbeda dari level pertama.
compare_levels() {   # $1=file hasil acuan  $2=file hasil pembanding  $3=tag acuan  $4=tag pembanding
    [ -f "$1" ] && [ -f "$2" ] || { echo "  (file hasil $3/$4 tidak lengkap, perbandingan dilewati)"; return; }
    awk -F' : ' -v A="$3" -v B="$4" '
        function proc(x,  m) { return match(x, /processed=[0-9]+/) ? substr(x, RSTART+10, RLENGTH-10) : "NA" }
        FNR==NR { if ($0 !~ /^#/ && NF>=3 && $1!="") { s1[$1]=$2; p1[$1]=proc($3) } next }
        $0 !~ /^#/ && NF>=3 && $1!="" { s2[$1]=$2; p2[$1]=proc($3) }
        END {
            n=0; same=0
            for (k in s1) if (k in s2) {
                if (s1[k]!=s2[k]) { printf "  %-40s %s=%-14s (processed=%s)  %s=%-14s (processed=%s)\n", k, A, s1[k], p1[k], B, s2[k], p2[k]; n++ }
                else same++
            }
            printf "  status sama: %d model, status berbeda: %d model\n", same, n
        }' "$1" "$2" | sort
}

if [ "${#LEVELS[@]}" -gt 1 ]; then
    trap 'exit 130' INT TERM
    for lvl in "${LEVELS[@]}"; do
        echo "================ level optimisasi: $lvl ================"
        _IN_MULTI=1 OPTS="$lvl" bash "$SELF"; rc=$?
        [ "$rc" -ge 130 ] && exit "$rc"
    done
    echo
    echo "================ perbandingan antar level ================"
    base="${LEVELS[0]}"
    for lvl in "${LEVELS[@]:1}"; do
        echo "-- ${base} vs ${lvl} (hanya model yang statusnya berbeda) --"
        compare_levels "$WORKDIR/verifier_results_$(tag_of "$base").txt" \
                       "$WORKDIR/verifier_results_$(tag_of "$lvl").txt" "$(tag_of "$base")" "$(tag_of "$lvl")"
    done
    exit 0
fi

# ── Dari sini: menjalankan SATU level (OPT) ────────────────────────────────────
OPT="${LEVELS[0]}"
RESULTS="$WORKDIR/verifier_results_$(tag_of "$OPT").txt"
LOGDIR="$WORKDIR/verifier_logs_$(tag_of "$OPT")"
N_FEAT="${N_FEAT:-9}"
ONLY="${ONLY:-DT RF MLP}"
FILTER="${FILTER:-}"
JOBS="${JOBS:-1}"
TIMEOUT="${TIMEOUT:-900}"
RESUME="${RESUME:-0}"
BPF_FLAGS=("$OPT" -fno-builtin-memset -target bpf -D__TARGET_ARCH_x86
           -I/usr/include/x86_64-linux-gnu "-DN_FEATURES=${N_FEAT}")

[ -f "$STUB" ] || { echo "Stub tidak ditemukan: $STUB"; exit 1; }
case "$PINDIR" in ""|"/"|"/sys"|"/sys/fs"|"/sys/fs/bpf") echo "PINDIR tidak aman: '$PINDIR'"; exit 1 ;; esac
case "$JOBS" in ''|*[!0-9]*|0) echo "JOBS harus bilangan >= 1"; exit 1 ;; esac
if [ "$PINDIR" = "/sys/fs/bpf/verifier_test" ] && ! mountpoint -q /sys/fs/bpf; then
    echo "PERINGATAN: /sys/fs/bpf belum di-mount (sudo mount -t bpf bpf /sys/fs/bpf)"
fi

TMPD="$(mktemp -d)"
KEEPALIVE_PID=""
cleanup() {
    local p
    [ -n "$KEEPALIVE_PID" ] && kill "$KEEPALIVE_PID" 2>/dev/null
    p="$(jobs -p)"; [ -n "$p" ] && kill $p 2>/dev/null
    sudo rm -f "$PINDIR"/* 2>/dev/null
    rm -rf "$TMPD"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# sisa file sementara dari versi lama skrip (dibuat di folder kerja)
rm -f "$WORKDIR"/*_bpf.h

sudo -v || { echo "butuh sudo untuk bpftool"; exit 1; }
# Jaga sesi sudo tetap hidup selama batch panjang (disown: tidak dihitung di `jobs` milik launch()).
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) &
KEEPALIVE_PID=$!
disown "$KEEPALIVE_PID" 2>/dev/null

# ── ANSI Colors ────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    C_RESET='\033[0m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
    C_GREEN='\033[38;5;114m'; C_RED='\033[38;5;203m'; C_CYAN='\033[38;5;87m'
    C_GRAY='\033[38;5;245m'; C_WHITE='\033[38;5;255m'; C_BG_HEADER='\033[48;5;235m'
else
    C_RESET=''; C_BOLD=''; C_DIM=''; C_GREEN=''; C_RED=''
    C_CYAN=''; C_GRAY=''; C_WHITE=''; C_BG_HEADER=''
fi

hr() { printf "${C_DIM}%0.s─${C_RESET}" $(seq 1 72); echo; }
section() {
    echo
    printf "${C_BG_HEADER}${C_CYAN}${C_BOLD}  %-68s${C_RESET}\n" "$1"
    hr
}
badge_pass() { printf "${C_GREEN}${C_BOLD} PASS ${C_RESET}"; }
badge_fail() { printf "${C_RED}${C_BOLD} FAIL ${C_RESET}"; }

# ── Daftar header untuk beberapa glob (unik, urut natural) ─────────────────────
list_headers() {
    shopt -s nullglob nocaseglob
    local g f
    for g in "$@"; do
        for f in $g; do
            case "$f" in *_bpf.h) continue ;; esac
            [ -f "$f" ] && printf '%s\n' "$f"
        done
    done | sort -uV
}

# ── Nama fungsi X_<suffix>( di header (predict_proba / komentar tidak ikut) ────
detect_fn() {   # $1=header  $2=predict|normalize
    grep -oP "\b[A-Za-z_][A-Za-z0-9_]*_$2(?=\s*\()" "$1" | head -1
}

# ── Strip predict_proba (float) dari header emlearn ───────────────────────────
strip_bpf_header() {
    local src="$1" dst="$2"
    awk '
    function opens(s,  t) { t=s; return gsub(/\{/, "{", t) }
    function closes(s, t) { t=s; return gsub(/\}/, "}", t) }
    skip == 0 && /predict_proba[[:space:]]*\(/ {
        skip=1; depth=opens($0)-closes($0); if (depth <= 0) skip=0; next
    }
    skip == 1 { depth += opens($0)-closes($0); if (depth <= 0) skip=0; next }
    { print }
    ' "$src" > "$dst"
    # Paksa predict() menjadi always_inline.
    sed -Ei \
        's/^([[:space:]]*)(static[[:space:]]+)?(inline[[:space:]]+)?int32_t[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)_predict\(/static __attribute__((always_inline)) int32_t \4_predict(/' \
        "$dst"
    # Paksa juga fungsi *_tree_N() (DT/RF) always_inline: bila tidak ter-inline, nilai kembalian
    # tree jadi skalar tak terbatas dan `votes[_class]` ditolak verifier (penolakan palsu akibat compiler).
    sed -Ei \
        's/^([[:space:]]*)static[[:space:]]+inline[[:space:]]+int32_t[[:space:]]+([A-Za-z_][A-Za-z0-9_]*_tree_[0-9]+)\(/static __attribute__((always_inline)) int32_t \2(/' \
        "$dst"
}

record() { printf '%s : %s : %s\n' "$1" "$2" "$3" >> "$RESULTS"; }

# ── Klasifikasi kegagalan verifier dari log ────────────────────────────────────
classify_fail() {   # $1=log  $2=exit code  $3=processed
    local f="$1" rc="$2" proc="${3:-}"
    if [ "$rc" = "124" ]; then echo "timeout"; return; fi
    if [ -n "$proc" ] && [ "$proc" -ge 1000000 ] 2>/dev/null; then echo "state-explosion"; return; fi
    if grep -qiE "Argument list too long|program is too large|too many states" "$f"; then
        echo "state-explosion"
    elif grep -qiE "combined stack size|stack limit|stack depth" "$f"; then
        echo "stack-limit"
    elif grep -qiE "back-edge|infinite loop" "$f"; then
        echo "loop"
    elif grep -qiE "bitwise operator .* on pointer|pointer arithmetic .*prohibited|pointer .* pointer prohibited" "$f"; then
        echo "pointer-arith"
    elif grep -qiE "invalid (access|mem access|stack|indirect)|outside of the allowed|min value is negative|unbounded memory access|with unbounded|offset is outside" "$f"; then
        echo "bounds-check"
    elif grep -qi "Permission denied" "$f"; then
        echo "verifier-reject"
    else
        echo "unknown"
    fi
}

# ── Test satu model ────────────────────────────────────────────────────────────
test_model() {
    local h_file="$1" model_type="$2" name="$3"
    local bpf_h="$TMPD/${name}_bpf.h" obj="$TMPD/${name}.o" pin="$PINDIR/$name"
    local cerr="$TMPD/${name}.cerr" vlog="$TMPD/${name}.vlog"
    local predict_fn normalize_fn=""

    predict_fn="$(detect_fn "$WORKDIR/$h_file" predict)"
    if [ -z "$predict_fn" ]; then
        printf "  $(badge_fail) ${C_BOLD}%-36s${C_RESET} ${C_DIM}compile: no *_predict() in header${C_RESET}\n" "$name"
        record "$name" COMPILE_FAIL "no *_predict() found in header"
        return
    fi
    [ "$model_type" = "MLP" ] && normalize_fn="$(detect_fn "$WORKDIR/$h_file" normalize)"

    strip_bpf_header "$WORKDIR/$h_file" "$bpf_h"

    local -a flags=("${BPF_FLAGS[@]}")
    flags+=("-DMODEL_H=\"$bpf_h\"" "-DMODEL_TYPE_${model_type}=1" "-DMODEL_PREDICT_FN=${predict_fn}")
    [ -n "$normalize_fn" ] && flags+=("-DMODEL_NORMALIZE_FN=${normalize_fn}")

    # Compile
    if ! clang "${flags[@]}" -c "$STUB" -o "$obj" 2>"$cerr"; then
        local reason where
        reason=$(grep -oP '(error in backend: [^$\n]+|BPF stack limit[^$\n]+|error: [^\n]+)' "$cerr" | head -1 || true)
        [ -z "$reason" ] && reason=$(head -1 "$cerr" | sed 's/.*error: //')
        # lokasi error pertama (file:baris) -> tahu apakah dari header sistem atau header model
        where=$(grep -m1 -E ' error: ' "$cerr" | sed -E 's/: (fatal )?error: .*//' | tr ':' ';' | cut -c1-90 || true)
        mkdir -p "$LOGDIR" && head -n 40 "$cerr" > "$LOGDIR/$name.compile.log"
        printf "  $(badge_fail) ${C_BOLD}%-36s${C_RESET} ${C_DIM}compile: %s${C_RESET}\n" "$name" "${reason:0:50}"
        record "$name" COMPILE_FAIL "$reason at=${where:-NA}"
        rm -f "$bpf_h" "$cerr"
        return
    fi

    # Instruksi STATIS di object (termasuk stub) — BUKAN angka kompleksitas verifier
    local insn
    insn=$(llvm-objdump -d "$obj" 2>/dev/null | grep -cE '^\s*[0-9a-f]+:' || true)
    [ -z "$insn" ] && insn="?"

    # Load via kernel verifier. -d => log verifier (termasuk "processed N insns") ke stderr.
    sudo rm -f "$pin"
    local rc=0 processed states
    timeout "$TIMEOUT" sudo bpftool -d prog load "$obj" "$pin" 2>"$vlog" || rc=$?
    processed=$(grep -oP 'processed \K[0-9]+(?= insns)' "$vlog" | tail -1 || true)
    states=$(grep -oP 'total_states \K[0-9]+' "$vlog" | tail -1 || true)

    if [ "$rc" -eq 0 ]; then
        printf "  $(badge_pass) ${C_BOLD}%-36s${C_RESET} ${C_GRAY}insn=%-6s verifier_processed=%s${C_RESET}\n" \
            "$name" "$insn" "${processed:-NA}"
        record "$name" PASS "insn=$insn processed=${processed:-NA} states=${states:-NA}"
        sudo rm -f "$pin"
    else
        local kind why
        kind="$(classify_fail "$vlog" "$rc" "$processed")"
        # baris error paling spesifik dulu (pesan verifier), baru yang generik
        why=$(grep -E '^R[0-9]+ |prohibited|invalid|unbounded|outside|too (large|many)' "$vlog" \
              | tail -1 | tr -s ' ' | tr ':' ';' | cut -c1-110 || true)
        [ -z "$why" ] && why=$(grep -E 'Error|error|failed' "$vlog" | tail -1 | tr -s ' ' | tr ':' ';' | cut -c1-110 || true)
        [ -z "$why" ] && why=$(tail -n 2 "$vlog" | tr '\n' ' ' | tr -s ' ' | tr ':' ';' | cut -c1-110)
        mkdir -p "$LOGDIR" && tail -n 300 "$vlog" > "$LOGDIR/$name.log"
        printf "  $(badge_fail) ${C_BOLD}%-36s${C_RESET} ${C_RED}verifier: %s${C_RESET}\n" "$name" "$kind"
        record "$name" VERIFIER_FAIL "$kind processed=${processed:-NA} why=${why:-NA}"
        sudo rm -f "$pin"
    fi

    rm -f "$obj" "$bpf_h" "$cerr" "$vlog"
}

# ── Jalankan (opsional paralel) ────────────────────────────────────────────────
launch() {
    if [ "$JOBS" -le 1 ]; then
        "$@"
    else
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n 2>/dev/null || true; done
        "$@" &
    fi
}

run_group() {   # $1=tipe  sisanya=glob
    local type="$1" h base; shift
    for h in $(list_headers "$@"); do
        base=$(basename "$h" .h)
        if [ -n "$FILTER" ] && ! [[ "$base" =~ $FILTER ]]; then continue; fi
        if [ "$RESUME" = "1" ] && grep -qE "^${base} : " "$RESULTS" 2>/dev/null; then continue; fi
        launch test_model "$h" "$type" "$base"
    done
    wait
}

want() { case " $ONLY " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# ── Preflight: toolchain + izin load harus beres SEBELUM memproses ratusan model ─
sudo mkdir -p "$PINDIR"
preflight() {
    local h="$TMPD/pf_bpf.h" o="$TMPD/pf.o" e="$TMPD/pf.err"
    printf '#include <stdint.h>\nstatic inline int32_t pf_predict(const int32_t *f, int n){ return f[0] < 5 ? 0 : 1; }\n' > "$h"
    if ! clang "${BPF_FLAGS[@]}" "-DMODEL_H=\"$h\"" -DMODEL_TYPE_DT=1 -DMODEL_PREDICT_FN=pf_predict \
           -c "$STUB" -o "$o" 2>"$e"; then
        echo "PREFLIGHT GAGAL: toolchain tidak bisa meng-compile stub dengan model dummy."
        echo "Ini masalah lingkungan/stub, BUKAN model. 25 baris pertama log clang:"
        head -n 25 "$e"
        echo
        echo "#include di $STUB (urutan penting: linux/types.h, linux/bpf.h, lalu bpf/bpf_helpers.h):"
        grep -n '#include' "$STUB" | head -8
        echo
        echo "Cek: dpkg -l | grep -E 'libbpf-dev|linux-libc-dev|libc6-dev-i386|clang'"
        echo "     ls /usr/include/linux/types.h /usr/include/x86_64-linux-gnu/asm/types.h /usr/include/bpf/bpf_helpers.h"
        echo "env: CPATH=${CPATH:-<unset>} C_INCLUDE_PATH=${C_INCLUDE_PATH:-<unset>} TMPDIR=${TMPDIR:-<unset>}"
        return 1
    fi
    sudo rm -f "$PINDIR/preflight"
    if ! sudo bpftool prog load "$o" "$PINDIR/preflight" 2>"$e"; then
        echo "PREFLIGHT GAGAL: bpftool tidak bisa me-load program dummy (izin/bpffs?)."
        head -n 15 "$e"; return 1
    fi
    sudo rm -f "$PINDIR/preflight"
    return 0
}
if [ "${SKIP_PREFLIGHT:-0}" != "1" ]; then
    preflight || exit 1
    echo "preflight OK (clang + bpftool + stub)"
fi

# ── Header hasil ───────────────────────────────────────────────────────────────
if [ "$RESUME" = "1" ] && [ -f "$RESULTS" ]; then
    echo "# --- resumed $(date) flags: ${BPF_FLAGS[*]} ---" >> "$RESULTS"
else
    [ -f "$RESULTS" ] && cp "$RESULTS" "$RESULTS.prev"
    {
        echo "# eBPF Verifier Results -- $(date)"
        echo "# Method: bpftool -d prog load (kernel.org/doc/html/latest/bpf/verifier.html)"
        echo "# clang : $(clang --version | head -1)"
        echo "# kernel: $(uname -r)"
        echo "# flags : ${BPF_FLAGS[*]}"
        echo ""
    } > "$RESULTS"
fi

[ -t 1 ] && [ -z "${_IN_MULTI:-}" ] && clear
printf "\n"
printf "${C_BG_HEADER}${C_WHITE}${C_BOLD}  %-68s${C_RESET}\n" "eBPF/XDP Model Compatibility Verifier"
printf "${C_BG_HEADER}${C_GRAY}  %-68s${C_RESET}\n" "Kernel $(uname -r)   Clang $(clang --version | grep -oP '\d+\.\d+\.\d+' | head -1)   flags: ${OPT}   jobs: ${JOBS}"
hr

if want DT; then
    section "Decision Tree  (emlearn inline)"
    run_group DT "Run*_DT*.h" "DT_*.h" "dt_*.h"
fi
if want RF; then
    section "Random Forest  (emlearn inline)"
    run_group RF "Run*_RF*.h" "RF_*.h" "rf_*.h"
fi
if want MLP; then
    section "MLP  (int32 quantized, Q14/Q30 fixed-point)"
    run_group MLP "Run*_MLP*.h" "MLP_*.h" "mlp_*.h"
fi

# ── Summary (dihitung dari file hasil, jadi benar juga untuk RESUME/JOBS>1) ────
count() { grep -cE "$1" "$RESULTS" 2>/dev/null || true; }
n_pass=$(count ' : PASS : ')
n_cf=$(count ' : COMPILE_FAIL : ')
n_vf=$(count ' : VERIFIER_FAIL : ')
echo
hr
printf "${C_BG_HEADER}${C_WHITE}${C_BOLD}  %-68s${C_RESET}\n" "Summary (seluruh isi file hasil)"
hr
printf "  ${C_WHITE}Total   : ${C_BOLD}%d${C_RESET}\n" "$((n_pass + n_cf + n_vf))"
printf "  ${C_GREEN}Passed  : ${C_BOLD}%d${C_RESET}\n" "$n_pass"
printf "  ${C_RED}Failed  : ${C_BOLD}%d${C_RESET}  ${C_DIM}(compile: %d, verifier: %d)${C_RESET}\n" \
    "$((n_cf + n_vf))" "$n_cf" "$n_vf"
for m in DT RF MLP; do
    printf "  ${C_GRAY}%-4s PASS=%s  VERIFIER_FAIL=%s  COMPILE_FAIL=%s${C_RESET}\n" "$m" \
        "$(grep -ciE "^([^ :]*_)?${m}_[^ ]* : PASS : " "$RESULTS" || true)" \
        "$(grep -ciE "^([^ :]*_)?${m}_[^ ]* : VERIFIER_FAIL : " "$RESULTS" || true)" \
        "$(grep -ciE "^([^ :]*_)?${m}_[^ ]* : COMPILE_FAIL : " "$RESULTS" || true)"
done
printf "  ${C_GRAY}Results : %s${C_RESET}\n" "$RESULTS"
[ "$n_vf" -gt 0 ] && printf "  ${C_GRAY}Logs    : %s/<nama>.log (300 baris terakhir, hanya yang gagal)${C_RESET}\n" "$LOGDIR"
hr
printf "\n"

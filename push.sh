#!/usr/bin/env bash

# ==============================================================================
# Git Automated Push & Optional Tagging Script
# Repository: robyajo/laravel-security-monitor
#
# Setiap kali dijalankan, skrip ini SELALU melakukan pengecekan versi:
#   - Versi sekarang    : tag rilis semver terakhir (mis. v1.0.3)
#   - Versi direkomendasi: kenaikan otomatis (major/minor/patch) dihitung dari
#                          commit & perubahan yang belum di-tag
#
# Gunakan "-t auto" untuk langsung memakai versi rekomendasi sebagai tag rilis.
# ==============================================================================

set -e

# Warna Terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper Functions
print_header() {
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BOLD}${CYAN}  🛡️  Laravel Security Monitor — Git Push & Tagging Helper${NC}"
    echo -e "${BLUE}======================================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ $1${NC}"
}

# ==============================================================================
# PENGECEKAN VERSI
# ==============================================================================

# Ambil tag rilis semver terakhir (diurutkan secara version-aware).
get_current_tag() {
    git tag -l 'v[0-9]*' --sort=-v:refname 2>/dev/null | head -n1
}

# Ambil komponen angka ke-N dari versi (tanpa prefix 'v'); default 0.
_version_part() {
    local part
    part=$(printf '%s' "$1" | cut -d. -f"$2")
    part=${part//[!0-9]/}
    echo "${part:-0}"
}

# Naikkan versi sesuai tipe bump: major | minor | patch.
bump_version() {
    local version="$1"
    local type="$2"
    local major minor patch

    major=$(_version_part "$version" 1)
    minor=$(_version_part "$version" 2)
    patch=$(_version_part "$version" 3)

    case "$type" in
        major) major=$((major + 1)); minor=0; patch=0 ;;
        minor) minor=$((minor + 1)); patch=0 ;;
        *)     patch=$((patch + 1)) ;;
    esac

    echo "${major}.${minor}.${patch}"
}

# Tentukan tipe bump dari Conventional Commits antara tag terakhir dan HEAD.
detect_bump_type() {
    local range="$1"
    local log

    if [ -n "$range" ] && git rev-parse "$range" >/dev/null 2>&1; then
        log=$(git log "$range" --pretty=format:'%s%n%b' 2>/dev/null || true)
    else
        log=$(git log --pretty=format:'%s%n%b' 2>/dev/null || true)
    fi

    if printf '%s' "$log" | grep -qE 'BREAKING[ _-]?CHANGE|[[:alnum:]]+(\([^)]+\))?!: '; then
        echo "major"
        return
    fi

    if printf '%s' "$log" | grep -qE '^feat(\([^)]+\))?!?: '; then
        echo "minor"
        return
    fi

    echo "patch"
}

# Hitung & tampilkan versi sekarang vs versi yang direkomendasikan.
report_versions() {
    local ahead uncommitted log_range

    CURRENT_TAG=$(get_current_tag)
    if [ -n "$CURRENT_TAG" ]; then
        CURRENT_VERSION="${CURRENT_TAG#v}"
    else
        CURRENT_VERSION="0.0.0"
    fi

    if [ -n "$CURRENT_TAG" ]; then
        ahead=$(git rev-list --count "${CURRENT_TAG}..HEAD" 2>/dev/null || echo 0)
        log_range="${CURRENT_TAG}..HEAD"
    else
        ahead=$(git rev-list --count HEAD 2>/dev/null || echo 0)
        log_range=""
    fi
    uncommitted=$(git status --porcelain | wc -l | tr -d ' ')

    if [ "$ahead" -eq 0 ] && [ "$uncommitted" -eq 0 ]; then
        BUMP_TYPE="none"
        RECOMMENDED_VERSION="$CURRENT_VERSION"
    else
        BUMP_TYPE=$(detect_bump_type "$log_range")
        RECOMMENDED_VERSION=$(bump_version "$CURRENT_VERSION" "$BUMP_TYPE")
    fi
    RECOMMENDED_TAG="v${RECOMMENDED_VERSION}"

    echo -e "${BOLD}${CYAN}----------------------------------------------------------------------${NC}"
    echo -e "${BOLD}  📦 Pengecekan Versi${NC}"
    echo -e "${BOLD}${CYAN}----------------------------------------------------------------------${NC}"

    if [ -n "$CURRENT_TAG" ]; then
        print_info "Versi sekarang       : ${BOLD}v${CURRENT_VERSION}${NC}  (tag terakhir: ${CURRENT_TAG})"
    else
        print_info "Versi sekarang       : ${BOLD}v${CURRENT_VERSION}${NC}  (belum ada tag rilis)"
    fi

    print_info "Belum di-tag         : ${BOLD}${ahead}${NC} commit, ${BOLD}${uncommitted}${NC} berkas belum di-commit"

    if [ "$BUMP_TYPE" = "none" ]; then
        print_warning "Versi direkomendasi  : ${BOLD}${RECOMMENDED_TAG}${NC} (tidak ada perubahan baru)"
    else
        print_info "Versi direkomendasi  : ${BOLD}${GREEN}${RECOMMENDED_TAG}${NC}  (${BUMP_TYPE} bump)"
    fi
    echo ""
}

# Tampilkan Bantuan
show_help() {
    print_header
    echo -e "${BOLD}PENGGUNAAN:${NC}"
    echo -e "  ./push.sh [OPSI]"
    echo -e "  ./push.sh \"Pesan commit\""
    echo -e "  ./push.sh \"Pesan commit\" \"v1.0.0\""
    echo ""
    echo -e "${BOLD}OPSI:${NC}"
    echo -e "  -m, --message <msg>   Pesan commit git"
    echo -e "  -t, --tag <tag>       Nama tag rilis (opsional, misal: v1.0.0)"
    echo -e "                        Gunakan 'auto' untuk memakai versi rekomendasi"
    echo -e "  -b, --branch <name>   Nama branch target (default: branch aktif)"
    echo -e "  -r, --remote <name>   Nama remote git (default: origin)"
    echo -e "  -h, --help            Tampilkan bantuan ini"
    echo ""
    echo -e "${BOLD}CONTOH:${NC}"
    echo -e "  ./push.sh"
    echo -e "  ./push.sh -m \"docs: update installation guide\""
    echo -e "  ./push.sh -m \"release: launch v1.0.0\" -t \"v1.0.0\""
    echo -e "  ./push.sh -m \"fix: patch bug\" -t auto"
    echo ""
    echo -e "${BOLD}CATATAN:${NC}"
    echo -e "  Pengecekan versi (sekarang vs rekomendasi) SELALU dijalankan."
    exit 0
}

# Parsing Argumen
COMMIT_MSG=""
TAG_NAME=""
REMOTE_NAME="origin"
TARGET_BRANCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--message)
            COMMIT_MSG="$2"
            shift 2
            ;;
        -t|--tag)
            TAG_NAME="$2"
            shift 2
            ;;
        -b|--branch)
            TARGET_BRANCH="$2"
            shift 2
            ;;
        -r|--remote)
            REMOTE_NAME="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            if [ -z "$COMMIT_MSG" ]; then
                COMMIT_MSG="$1"
            elif [ -z "$TAG_NAME" ]; then
                TAG_NAME="$1"
            fi
            shift
            ;;
    esac
done

# Pastikan berada di dalam repositori git
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    print_error "Direktori saat ini bukan repositori Git!"
    exit 1
fi

print_header

# Deteksi branch saat ini jika tidak dispesifikasikan
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ -z "$TARGET_BRANCH" ]; then
    TARGET_BRANCH="$CURRENT_BRANCH"
fi

print_info "Remote target : ${BOLD}${REMOTE_NAME}${NC}"
print_info "Branch target : ${BOLD}${TARGET_BRANCH}${NC}"
echo ""

# 0. Pengecekan Versi (WAJIB, selalu dijalankan)
report_versions

# 1. Periksa Status Perubahan File
STATUS_OUTPUT=$(git status --porcelain)

if [ -n "$STATUS_OUTPUT" ]; then
    echo -e "${BOLD}Perubahan berkas yang terdeteksi:${NC}"
    git status -s
    echo ""

    # Jika pesan commit belum diberikan lewat argumen, minta input interaktif
    if [ -z "$COMMIT_MSG" ]; then
        if [ -t 0 ]; then
            echo -ne "${BOLD}Masukkan pesan commit${NC} (default: 'chore: update repository files'): "
            read -r INPUT_MSG
            if [ -n "$INPUT_MSG" ]; then
                COMMIT_MSG="$INPUT_MSG"
            else
                COMMIT_MSG="chore: update repository files"
            fi
        else
            COMMIT_MSG="chore: update repository files"
        fi
    fi

    # Lakukan git add & commit
    echo ""
    print_info "Menambahkan perubahan ke staging (git add -A)..."
    git add -A

    print_info "Membuat commit: \"${COMMIT_MSG}\"..."
    git commit -m "$COMMIT_MSG"
    print_success "Perubahan berhasil di-commit."
else
    print_info "Tidak ada perubahan berkas yang belum di-commit."
fi

# 2. Push ke Remote Git
echo ""
print_info "Mendorong commit ke ${REMOTE_NAME}/${TARGET_BRANCH}..."
git push "$REMOTE_NAME" "$TARGET_BRANCH"
print_success "Commit berhasil di-push ke ${REMOTE_NAME}/${TARGET_BRANCH}!"

# 3. Penanganan Tag (Opsional)
echo ""

# Resolusi kata kunci 'auto' menjadi versi rekomendasi.
if [ "$TAG_NAME" = "auto" ]; then
    TAG_NAME="$RECOMMENDED_TAG"
    print_info "Mode 'auto': memakai versi rekomendasi ${BOLD}${TAG_NAME}${NC}."
fi

if [ -z "$TAG_NAME" ]; then
    if [ -t 0 ]; then
        echo -ne "${BOLD}Apakah Anda ingin membuat Git Tag rilis baru sekarang? (y/N): ${NC}"
        read -r WANT_TAG
        if [[ "$WANT_TAG" =~ ^[yY]([eE][sS])?$ ]]; then
            echo -ne "${BOLD}Masukkan nama tag${NC} (contoh: v1.0.0) [default: ${RECOMMENDED_TAG}]: "
            read -r INPUT_TAG
            if [ -n "$INPUT_TAG" ]; then
                TAG_NAME="$INPUT_TAG"
            else
                TAG_NAME="$RECOMMENDED_TAG"
            fi
        fi
    fi
fi

if [ -n "$TAG_NAME" ]; then
    # Peringatan bila tag sama dengan versi sekarang (tidak menaikkan versi)
    if [ -n "$CURRENT_TAG" ] && [ "$TAG_NAME" = "$CURRENT_TAG" ]; then
        print_warning "Tag '${TAG_NAME}' sama dengan tag terakhir. Naikkan versi (rekomendasi: ${RECOMMENDED_TAG})."
    fi

    # Validasi apakah tag sudah pernah ada sebelumnya
    if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
        print_warning "Tag '${TAG_NAME}' sudah ada di repositori lokal."
        OVERWRITE_TAG="n"
        if [ -t 0 ]; then
            echo -ne "Apakah Anda ingin menimpa (force update) tag ini? (y/N): "
            read -r OVERWRITE_TAG
        fi
        if [[ "$OVERWRITE_TAG" =~ ^[yY]([eE][sS])?$ ]]; then
            git tag -d "$TAG_NAME" > /dev/null 2>&1 || true
            git push "$REMOTE_NAME" --delete "$TAG_NAME" > /dev/null 2>&1 || true
            git tag -a "$TAG_NAME" -m "Release $TAG_NAME"
            print_info "Mendorong tag baru ke remote..."
            git push "$REMOTE_NAME" "$TAG_NAME"
            print_success "Tag '${TAG_NAME}' berhasil diperbarui dan di-push!"
        else
            print_info "Pembuatan tag dibatalkan."
        fi
    else
        TAG_COMMENT=""
        if [ -t 0 ]; then
            echo -ne "${BOLD}Masukkan keterangan rilis untuk tag ${TAG_NAME}${NC} (default: 'Release ${TAG_NAME}'): "
            read -r TAG_COMMENT
        fi
        if [ -z "$TAG_COMMENT" ]; then
            TAG_COMMENT="Release $TAG_NAME"
        fi

        print_info "Membuat annotated tag: ${TAG_NAME}..."
        git tag -a "$TAG_NAME" -m "$TAG_COMMENT"

        print_info "Mendorong tag ${TAG_NAME} ke ${REMOTE_NAME}..."
        git push "$REMOTE_NAME" "$TAG_NAME"
        print_success "Tag '${TAG_NAME}' berhasil dibuat dan di-push ke ${REMOTE_NAME}!"

        echo ""
        print_info "🚀 Paket versi ${TAG_NAME} kini siap dideteksi secara otomatis oleh Packagist!"
        echo -e "   Periksa katalog rilis di: ${BLUE}https://packagist.org/packages/robyajo/laravel-security-monitor${NC}"
    fi
else
    print_info "Melewatkan pembuatan tag (tidak ada tag yang ditentukan)."
    echo -e "   ${BOLD}Rekomendasi tag:${NC} ${GREEN}${RECOMMENDED_TAG}${NC} — jalankan: ./push.sh -t auto"
fi

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}  ✨ Selesai! Seluruh proses Git berhasil dieksekusi dengan lancar.${NC}"
echo -e "${GREEN}======================================================================${NC}"

#!/data/data/com.termux/files/usr/bin/bash
# BusinessOS authentication.js deployment helper for Termux.
# Pushes the selected file to the current Git remote (GitHub Pages workflow)
# and deploys the configured Firebase Hosting site for business-os-by.

set -Eeuo pipefail

PROJECT_ID="business-os-by"

say() { printf '\n[BusinessOS] %s\n' "$*"; }
fail() { printf '\n[ERROR] %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || fail "Git is not installed. Install it with: pkg install git"
command -v firebase >/dev/null 2>&1 || fail "Firebase CLI is not installed. Install it with: npm install -g firebase-tools"
command -v node >/dev/null 2>&1 || fail "Node.js is not installed. Install it with: pkg install nodejs"

printf 'Enter the full path to your BusinessOS project folder.\n'
printf 'Press ENTER to use the current folder: '
IFS= read -r PROJECT_DIR
PROJECT_DIR="${PROJECT_DIR:-$PWD}"

[ -d "$PROJECT_DIR" ] || fail "Project folder does not exist: $PROJECT_DIR"
cd "$PROJECT_DIR"

[ -d .git ] || fail "This folder is not the root of a Git repository. Open the BusinessOS repository folder and run the script again."
[ -f firebase.json ] || fail "firebase.json was not found in this project folder."

REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"
[ -n "$REMOTE_URL" ] || fail "Git remote 'origin' is missing. Add your BusinessOS GitHub repository as origin first."

BRANCH="$(git branch --show-current)"
[ -n "$BRANCH" ] || fail "Git is in detached-HEAD mode. Switch to your normal deployment branch first."

# Discover the hosting public directory from firebase.json.
PUBLIC_DIR="$(node -e '
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync("firebase.json", "utf8"));
const hosting = Array.isArray(cfg.hosting) ? cfg.hosting[0] : cfg.hosting;
if (!hosting || typeof hosting.public !== "string" || !hosting.public.trim()) process.exit(2);
process.stdout.write(hosting.public);
' 2>/dev/null)" || fail "Could not read the Firebase Hosting public directory from firebase.json."

PUBLIC_DIR="$(node -e 'const path = require("path"); process.stdout.write(path.resolve(process.cwd(), process.argv[1]));' "$PUBLIC_DIR")"
PROJECT_ROOT="$(pwd -P)"
case "$PUBLIC_DIR/" in
    "$PROJECT_ROOT/"*) ;;
    *) fail "The Firebase Hosting public directory is outside this repository. This script will not deploy an unrelated folder." ;;
esac

[ -d "$PUBLIC_DIR" ] || fail "Firebase Hosting public directory does not exist: $PUBLIC_DIR"

# Find the actual authentication.js file inside the repository, excluding
# generated/dependency folders. If several copies exist, ask which one to deploy.
mapfile -t AUTH_FILES < <(find . \
    -path './.git' -prune -o \
    -path './node_modules' -prune -o \
    -path './.firebase' -prune -o \
    -type f -name 'authentication.js' -print | sort)

[ "${#AUTH_FILES[@]}" -gt 0 ] || fail "No authentication.js file was found inside the repository. Put the updated file in the correct project location first."

if [ "${#AUTH_FILES[@]}" -eq 1 ]; then
    AUTH_REL="${AUTH_FILES[0]}"
else
    say "More than one authentication.js file was found:"
    for i in "${!AUTH_FILES[@]}"; do
        printf '  %s) %s\n' "$((i + 1))" "${AUTH_FILES[$i]}"
    done
    printf 'Choose the file number to deploy: '
    IFS= read -r PICK
    [[ "$PICK" =~ ^[0-9]+$ ]] || fail "Invalid selection."
    (( PICK >= 1 && PICK <= ${#AUTH_FILES[@]} )) || fail "Selection is outside the listed range."
    AUTH_REL="${AUTH_FILES[$((PICK - 1))]}"
fi

AUTH_ABS="$(node -e 'const fs = require("fs"); process.stdout.write(fs.realpathSync(process.argv[1]));' "$AUTH_REL")"
case "$AUTH_ABS" in
    "$PUBLIC_DIR"/*) ;;
    *) fail "Selected file is not inside Firebase Hosting's public directory ($PUBLIC_DIR). It would not be included in the Firebase Hosting deployment." ;;
esac

say "Selected file: $AUTH_REL"
say "Firebase Hosting directory: ${PUBLIC_DIR#"$PROJECT_ROOT"/}"
say "Git remote: $REMOTE_URL"
say "Git branch: $BRANCH"

# Syntax validation. This checks JavaScript parsing without trying to load
# browser Firebase CDN imports in Node.
node --check "$AUTH_ABS" || fail "JavaScript syntax validation failed. Nothing has been committed or deployed."

# Confirm Firebase CLI access and the intended project.
say "Checking Firebase CLI access..."
if ! firebase projects:list --json >/dev/null 2>&1; then
    say "Firebase CLI is not authenticated. Starting Firebase login..."
    firebase login
fi

# Do not accidentally include unrelated files that were already staged.
if ! git diff --cached --quiet; then
    say "The Git staging area already contains other changes."
    git status --short
    fail "Commit or unstage those existing staged changes first. This script stages only authentication.js."
fi

# Stage only authentication.js, commit it, then push the current branch.
git add -- "$AUTH_REL"
if git diff --cached --quiet; then
    say "No Git changes detected in $AUTH_REL. The file already matches the committed version."
else
    git commit -m "Fix BusinessOS authentication profile synchronization"
fi

git push -u origin "$BRANCH"
say "GitHub push completed. Your GitHub Pages Actions workflow will deploy according to its configured branch trigger."

# Deploy Firebase Hosting only (no Firestore rules, functions, or other services).
say "Deploying Firebase Hosting for project $PROJECT_ID..."
firebase deploy --only hosting --project "$PROJECT_ID"

say "Deployment commands completed."
say "GitHub Pages deployment runs through the repository's configured GitHub Actions workflow. Check the Actions tab for its final status."
say "Firebase Hosting deployment targeted only the hosting service in project $PROJECT_ID."

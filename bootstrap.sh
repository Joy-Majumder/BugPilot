#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$DIR"

echo "[*] Creating virtual environment at $PROJECT_DIR/venv"
python3 -m venv "$PROJECT_DIR/venv"

echo "[*] Activating venv and upgrading pip"
source "$PROJECT_DIR/venv/bin/activate"
pip install --upgrade pip wheel setuptools

echo "[*] Installing Python dependencies"
pip install -r "$PROJECT_DIR/requirements.txt"

echo "[*] Setting up Playwright browsers in local tools directory"
export PLAYWRIGHT_BROWSERS_PATH="$PROJECT_DIR/tools/pw-browsers"
playwright install chromium

echo "[*] Creating tools directory"
mkdir -p "$PROJECT_DIR/tools"

echo "[*] Downloading nuclei"
NUCLEI_VERSION="v3.3.2"
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip"
if [[ "$OSTYPE" == "darwin"* ]]; then
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_macos_arm64.zip"
fi

curl -sL "$NUCLEI_URL" -o "$PROJECT_DIR/tools/nuclei.zip"
cd "$PROJECT_DIR/tools" && unzip -o nuclei.zip && rm nuclei.zip
chmod +x "$PROJECT_DIR/tools/nuclei"

echo "[*] Downloading nuclei templates"
"$PROJECT_DIR/tools/nuclei" -update-templates -update-template-dir "$PROJECT_DIR/tools/nuclei-templates" -silent

echo "[*] Downloading subfinder"
SUBFINDER_VERSION="v2.6.6"
SUBFINDER_URL="https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_amd64.zip"
if [[ "$OSTYPE" == "darwin"* ]]; then
    SUBFINDER_URL="https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_macos_arm64.zip"
fi

curl -sL "$SUBFINDER_URL" -o "$PROJECT_DIR/tools/subfinder.zip"
cd "$PROJECT_DIR/tools" && unzip -o subfinder.zip && rm subfinder.zip
chmod +x "$PROJECT_DIR/tools/subfinder"

echo "[*] Downloading httpx"
HTTPX_VERSION="v1.6.8"
HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_amd64.zip"
if [[ "$OSTYPE" == "darwin"* ]]; then
    HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_macos_arm64.zip"
fi

curl -sL "$HTTPX_URL" -o "$PROJECT_DIR/tools/httpx.zip"
cd "$PROJECT_DIR/tools" && unzip -o httpx.zip && rm httpx.zip
chmod +x "$PROJECT_DIR/tools/httpx"

echo "[*] Installing sqlmap (vendored into venv)"
pip install sqlmap

echo "[*] Installing CLI entrypoint"
pip install -e "$PROJECT_DIR"

echo "[*] Creating .env from example if not exists"
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
fi

echo ""
echo "=========================================="
echo "[*] Bootstrap complete!"
echo "=========================================="
echo ""
echo "To run the web UI:"
echo "  cd $PROJECT_DIR"
echo "  source venv/bin/activate"
echo "  bugpilot serve"
echo ""
echo "Or use the CLI:"
echo "  bugpilot --help"
echo "  bugpilot scan --target https://example.com"
echo "  bugpilot serve"
echo ""
echo "Then open http://127.0.0.1:8080 in your browser"
echo ""
echo "All tools installed locally in:"
echo "  $PROJECT_DIR/venv/          (Python packages)"
echo "  $PROJECT_DIR/tools/         (nuclei, subfinder, httpx, playwright browsers)"
echo "  $PROJECT_DIR/data/          (SQLite DB, sessions, payloads)"
echo "  $PROJECT_DIR/reports/       (generated reports)"
"""Application entrypoint for FraudFence: "Smarter AI for Safer Conversations".

This module exposes a small programmatic API and a CLI interface that
accepts a suspicious message and returns a structured JSON assessment.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
from urllib.parse import urlparse

from scorer import ScamAssessment, assess_message
from utils import load_environment


def run_assessment(message: str, *, api_key: str | None = None) -> ScamAssessment:
    """Run a full scam assessment for the given message.

    This is the main programmatic API for other modules to call.
    """
    if not isinstance(message, str):
        raise TypeError("message must be a string.")

    stripped = message.strip()
    if not stripped:
        raise ValueError("message must not be empty or only whitespace.")

    return assess_message(stripped, api_key=api_key)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            'FraudFence: "Smarter AI for Safer Conversations" - analyze a suspicious '
            "message and return a JSON assessment."
        )
    )
    parser.add_argument(
        "-m",
        "--message",
        help="Suspicious message text to analyze. "
        "If omitted, the message is read from standard input.",
    )
    parser.add_argument(
        "--api-key",
        help=(
            "Gemini API key to use for this run. "
            "If omitted, GEMINI_API_KEY or GOOGLE_API_KEY from the environment is used."
        ),
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Start a local web UI instead of running a single CLI analysis.",
    )
    parser.add_argument(
        "--enable-web-search",
        action="store_true",
        help=(
            "Enable optional web search enrichment (requires SERPER_API_KEY or "
            "--serper-api-key)."
        ),
    )
    parser.add_argument(
        "--serper-api-key",
        help="Serper.dev API key (otherwise reads SERPER_API_KEY from environment).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface for --web mode (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for --web mode (default: 8000).",
    )
    return parser.parse_args(argv)


def _read_message_from_stdin() -> str:
    """Read a suspicious message from standard input."""
    data = sys.stdin.read()
    return data


def _web_ui_html() -> str:
    """Return the HTML for the local FraudFence UI."""
    return """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>FraudFence — Smarter AI for Safer Conversations</title>
    <style>
      :root{
        --bg:#0b1020;
        --panel:#101a33;
        --panel2:#0f1830;
        --text:#e9eefc;
        --muted:#a8b4d6;
        --accent:#6ea8fe;
        --danger:#ff6b6b;
        --ok:#4dd4ac;
        --border:rgba(255,255,255,.10);
        --shadow:0 20px 70px rgba(0,0,0,.45);
        --radius:18px;
      }
      *{box-sizing:border-box}
      body{
        margin:0;
        font-family:ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif;
        background:radial-gradient(1200px 800px at 20% 10%, #162657 0%, transparent 60%),
                   radial-gradient(1000px 700px at 80% 20%, #2a1f55 0%, transparent 55%),
                   var(--bg);
        color:var(--text);
        min-height:100vh;
      }
      .wrap{max-width:1400px;margin:0 auto;padding:34px 22px 44px;min-height:100vh}
      .header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:18px}
      .brand h1{margin:0;font-size:36px;letter-spacing:.2px}
      .brand p{margin:8px 0 0;color:var(--muted);font-size:16px}
      .grid{display:grid;grid-template-columns:520px 1fr;gap:20px}
      @media (max-width: 980px){.grid{grid-template-columns:1fr}}
      .card{
        background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
        border:1px solid var(--border);
        border-radius:var(--radius);
        box-shadow:var(--shadow);
        overflow:hidden;
      }
      .phone{padding:18px;background:linear-gradient(180deg, rgba(0,0,0,.15), rgba(0,0,0,.00))}
      .phoneShell{
        margin:0 auto;
        max-width:480px;
        background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
        border:1px solid var(--border);
        border-radius:26px;
        box-shadow:0 16px 50px rgba(0,0,0,.55);
        overflow:hidden;
      }
      .status{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;color:var(--muted);font-size:14px;border-bottom:1px solid var(--border)}
      .chat{padding:16px;background:linear-gradient(180deg, rgba(16,26,51,.55), rgba(16,26,51,.25))}
      .bubble{
        max-width:90%;
        padding:12px 14px;
        border-radius:16px;
        border:1px solid var(--border);
        line-height:1.45;
        font-size:16px;
        white-space:pre-wrap;
        word-break:break-word;
      }
      .bubble.in{background:rgba(255,255,255,.06);border-top-left-radius:6px}
      .bubble.out{background:rgba(110,168,254,.18);border-color:rgba(110,168,254,.35);margin-left:auto;border-top-right-radius:6px}
      .inputBar{display:flex;gap:10px;padding:12px;border-top:1px solid var(--border);background:rgba(15,24,48,.55)}
      textarea{
        width:100%;
        resize:vertical;
        min-height:110px;
        max-height:260px;
        padding:12px 14px;
        border-radius:14px;
        border:1px solid var(--border);
        background:rgba(0,0,0,.18);
        color:var(--text);
        outline:none;
        font-size:15px;
      }
      textarea:focus{border-color:rgba(110,168,254,.55);box-shadow:0 0 0 4px rgba(110,168,254,.12)}
      button{
        border:1px solid rgba(110,168,254,.45);
        background:rgba(110,168,254,.20);
        color:var(--text);
        padding:12px 14px;
        border-radius:14px;
        cursor:pointer;
        font-weight:600;
        white-space:nowrap;
        font-size:15px;
      }
      button:hover{background:rgba(110,168,254,.28)}
      button:disabled{opacity:.55;cursor:not-allowed}
      .panel{padding:22px}
      .panel h2{margin:0 0 12px;font-size:22px}
      .muted{color:var(--muted)}
      .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
      .badge{
        display:inline-flex;align-items:center;gap:8px;
        padding:10px 12px;border-radius:14px;border:1px solid var(--border);
        background:rgba(0,0,0,.18);
      }
      .dot{width:10px;height:10px;border-radius:50%}
      .dot.ok{background:var(--ok)}
      .dot.warn{background:var(--danger)}
      .kpi{font-size:34px;font-weight:800;letter-spacing:.2px}
      .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
      .chip{padding:8px 12px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.05);font-size:13px}
      .box{
        margin-top:12px;
        border:1px solid var(--border);
        background:rgba(0,0,0,.18);
        border-radius:16px;
        padding:12px 12px;
      }
      .box h3{margin:0 0 10px;font-size:15px;color:var(--muted);font-weight:800;letter-spacing:.2px}
      .box p{margin:0;line-height:1.55;font-size:15px}
      .footer{margin-top:16px;color:var(--muted);font-size:13px}
      code{background:rgba(255,255,255,.06);padding:2px 6px;border-radius:8px;border:1px solid var(--border)}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="header">
        <div class="brand">
          <h1>FraudFence</h1>
          <p>Smarter AI for Safer Conversations</p>
        </div>
        <div class="muted">Local UI • no data stored</div>
      </div>
      <div class="grid">
        <div class="card phone">
          <div class="phoneShell">
            <div class="status">
              <div>Messages</div>
              <div id="status">Ready</div>
            </div>
            <div class="chat">
              <div class="bubble in" id="previewBubble">
Paste or type the suspicious message below.
              </div>
            </div>
            <div class="inputBar">
              <textarea id="message" placeholder="Example: Your bank account will be locked. Verify now: https://..."></textarea>
              <button id="analyzeBtn">Analyze</button>
            </div>
          </div>
        </div>
        <div class="card panel">
          <h2>Assessment</h2>
          <div class="row" style="margin-bottom:10px">
            <label class="badge" style="cursor:pointer">
              <input id="webToggle" type="checkbox" style="transform:scale(1.15);margin-right:10px" />
              <div>
                <div class="muted">Web enrichment</div>
                <div style="font-weight:700">Use public snippets (optional)</div>
              </div>
            </label>
          </div>
          <div class="row">
            <div class="badge">
              <span class="dot" id="riskDot"></span>
              <div>
                <div class="muted">Scam probability</div>
                <div class="kpi" id="prob">—</div>
              </div>
            </div>
            <div class="badge">
              <div>
                <div class="muted">Category</div>
                <div class="kpi" style="font-size:18px" id="cat">—</div>
              </div>
            </div>
          </div>
          <div class="chips" id="flags"></div>
          <div class="box">
            <h3>Explanation</h3>
            <p id="explain" class="muted">Run an analysis to see a simple explanation.</p>
          </div>
          <div class="box">
            <h3>Safe response</h3>
            <p id="safe" class="muted">You’ll get clear advice on what to do next.</p>
          </div>
          <div class="box">
            <h3>AI model details (Gemini)</h3>
            <p class="muted" id="geminiSummary">Run an analysis to see the model’s internal assessment.</p>
            <ul id="geminiFlags" class="muted" style="margin-top:8px;padding-left:18px"></ul>
          </div>
          <div class="footer">
            Tip: set your Gemini key in <code>.env</code>. For optional web enrichment, set <code>SERPER_API_KEY</code>.
          </div>
        </div>
      </div>
    </div>
    <script>
      const elMsg = document.getElementById('message');
      const elPreview = document.getElementById('previewBubble');
      const elBtn = document.getElementById('analyzeBtn');
      const elStatus = document.getElementById('status');
      const elProb = document.getElementById('prob');
      const elCat = document.getElementById('cat');
      const elFlags = document.getElementById('flags');
      const elExplain = document.getElementById('explain');
      const elSafe = document.getElementById('safe');
      const elDot = document.getElementById('riskDot');
      const elWeb = document.getElementById('webToggle');
      const elGeminiSummary = document.getElementById('geminiSummary');
      const elGeminiFlags = document.getElementById('geminiFlags');

      function setBusy(b){
        elBtn.disabled = b;
        elStatus.textContent = b ? 'Analyzing…' : 'Ready';
      }

      function setDot(prob){
        if (typeof prob !== 'number') { elDot.className = 'dot'; return; }
        elDot.className = 'dot ' + (prob >= 60 ? 'warn' : 'ok');
      }

      function renderFlags(flags){
        elFlags.innerHTML = '';
        if (!Array.isArray(flags) || flags.length === 0) return;
        for (const f of flags){
          const chip = document.createElement('div');
          chip.className = 'chip';
          chip.textContent = f;
          elFlags.appendChild(chip);
        }
      }

      function renderGeminiDetails(details, errorText){
        elGeminiSummary.textContent = '';
        elGeminiFlags.innerHTML = '';
        if (errorText){
          elGeminiSummary.textContent = 'Gemini error: ' + errorText;
          return;
        }
        if (!details){
          elGeminiSummary.textContent = 'No Gemini analysis was available. The result is based on rules only.';
          return;
        }
        const score = typeof details.gemini_score === 'number' ? details.gemini_score : null;
        const cat = details.gemini_category || 'unknown';
        const flags = Array.isArray(details.gemini_flags) ? details.gemini_flags : [];
        elGeminiSummary.textContent = `Gemini score: ${score !== null ? score + '%' : 'n/a'} • Category: ${cat}`;
        for (const f of flags){
          const li = document.createElement('li');
          li.textContent = f;
          elGeminiFlags.appendChild(li);
        }
      }

      elMsg.addEventListener('input', () => {
        const t = elMsg.value.trim();
        elPreview.textContent = t ? t : 'Paste or type the suspicious message below.';
      });

      async function analyze(){
        const message = elMsg.value.trim();
        if (!message){
          elStatus.textContent = 'Please enter a message.';
          return;
        }
        setBusy(true);
        try{
          const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message, enable_web_search: !!(elWeb && elWeb.checked)})
          });
          const data = await res.json();
          if (!res.ok){
            throw new Error(data && data.error ? data.error : 'Request failed');
          }
          elProb.textContent = data.scam_probability + '%';
          elCat.textContent = data.scam_category;
          setDot(data.scam_probability);
          renderFlags(data.red_flags);
          elExplain.textContent = data.explanation;
          elSafe.textContent = data.safe_response;
          renderGeminiDetails(data.gemini_details, data.gemini_error || '');
          elStatus.textContent = 'Done';
        }catch(e){
          elStatus.textContent = 'Error: ' + (e && e.message ? e.message : 'Unknown error');
        }finally{
          setBusy(false);
        }
      }

      elBtn.addEventListener('click', analyze);
    </script>
  </body>
</html>
"""


def _start_web_server(
    host: str, port: int, *, api_key: str | None, serper_api_key: str | None
) -> None:
    """Start a local web server for the FraudFence UI."""

    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, payload: dict[str, object]) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path != "/":
                self.send_response(404)
                self.end_headers()
                return
            body = _web_ui_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path != "/api/analyze":
                self._send_json(404, {"error": "Not found"})
                return

            length_raw = self.headers.get("Content-Length", "0")
            try:
                length = int(length_raw)
            except ValueError:
                self._send_json(400, {"error": "Invalid Content-Length"})
                return

            body = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                self._send_json(400, {"error": "Request body must be valid JSON"})
                return

            message = parsed.get("message") if isinstance(parsed, dict) else None
            if not isinstance(message, str) or not message.strip():
                self._send_json(400, {"error": "Field 'message' must be a non-empty string"})
                return

            enable_web_search = False
            if isinstance(parsed, dict) and isinstance(parsed.get("enable_web_search"), bool):
                enable_web_search = parsed["enable_web_search"]

            try:
                result = assess_message(
                    message,
                    api_key=api_key,
                    enable_web_search=enable_web_search,
                    serper_api_key=serper_api_key,
                )
            except Exception as exc:  # noqa: BLE001
                self._send_json(500, {"error": str(exc)})
                return

            self._send_json(200, result)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer((host, port), Handler)
    sys.stdout.write(f"FraudFence web UI running at http://{host}:{port}/\n")
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    """Run the CLI interface."""
    load_environment()

    args = _parse_args(argv)
    if args.web:
        _start_web_server(
            args.host,
            args.port,
            api_key=args.api_key,
            serper_api_key=args.serper_api_key,
        )
        return 0

    message = args.message if args.message is not None else _read_message_from_stdin()

    try:
        assessment = assess_message(
            message,
            api_key=args.api_key,
            enable_web_search=args.enable_web_search,
            serper_api_key=args.serper_api_key,
        )
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    json_output = json.dumps(
        assessment,
        ensure_ascii=False,
        separators=(",", ": "),
    )
    sys.stdout.write(json_output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


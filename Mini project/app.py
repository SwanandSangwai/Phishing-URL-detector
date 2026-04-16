from pathlib import Path

from flask import Flask, request, render_template_string

from src.phishing_detector import explain_url_prediction, load_model, build_report, save_url_report

MODEL_PATH = Path("models/phishing_detector.joblib")
app = Flask(__name__)
model = load_model(MODEL_PATH)

TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Phishing URL Detector</title>
    <style>
      :root {
        --bg: #081229;
        --panel: rgba(255, 255, 255, 0.08);
        --surface: #111c3f;
        --surface-strong: #16255e;
        --text: #eff5ff;
        --muted: #b7c3e0;
        --accent: #5bb8ff;
        --danger: #ff6b6b;
        --success: #76d7b9;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        font-family: 'Inter', system-ui, sans-serif;
        color: var(--text);
        background: radial-gradient(circle at top left, rgba(91, 184, 255, 0.2), transparent 25%),
                    linear-gradient(180deg, #081229 0%, #0e1840 45%, #10183a 100%);
      }

      .page {
        max-width: 980px;
        margin: 0 auto;
        padding: 32px 24px 48px;
      }

      .hero {
        display: grid;
        gap: 18px;
        margin-bottom: 30px;
        padding: 28px;
        background: var(--panel);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 28px;
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.18);
      }

      .hero-title {
        display: flex;
        align-items: center;
        gap: 16px;
      }

      .hero-title svg {
        width: 48px;
        height: 48px;
        fill: var(--accent);
      }

      .hero h1 {
        margin: 0;
        font-size: clamp(2.3rem, 2.8vw, 3.4rem);
        line-height: 1.05;
      }

      .hero p {
        margin: 0;
        max-width: 700px;
        color: var(--muted);
        font-size: 1rem;
        line-height: 1.75;
      }

      .search-card {
        padding: 24px;
        border-radius: 24px;
        background: linear-gradient(135deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
        border: 1px solid rgba(255,255,255,0.08);
      }

      .input-group {
        display: grid;
        gap: 12px;
      }

      .input-label {
        display: flex;
        align-items: center;
        gap: 10px;
        color: var(--muted);
        font-weight: 600;
      }

      .input-label svg {
        width: 18px;
        height: 18px;
        fill: var(--accent);
      }

      input[type=text] {
        width: 100%;
        border: none;
        border-radius: 16px;
        padding: 16px 18px;
        font-size: 1rem;
        background: rgba(255,255,255,0.08);
        color: var(--text);
        outline: none;
        transition: box-shadow 0.2s ease;
      }

      input[type=text]:focus {
        box-shadow: 0 0 0 3px rgba(91, 184, 255, 0.18);
      }

      button {
        margin-top: 12px;
        border: none;
        border-radius: 16px;
        padding: 16px 24px;
        font-size: 1rem;
        font-weight: 700;
        color: #0b1632;
        background: linear-gradient(135deg, #5bb8ff, #2d78f4);
        cursor: pointer;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
      }

      button:hover {
        transform: translateY(-1px);
        box-shadow: 0 18px 40px rgba(34, 104, 255, 0.22);
      }

      .result {
        margin-top: 28px;
        padding: 26px;
        border-radius: 24px;
        background: var(--surface);
        border: 1px solid rgba(255,255,255,0.08);
      }

      .result strong {
        color: var(--text);
      }

      .result .status {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 10px 16px;
        border-radius: 999px;
        font-weight: 700;
      }

      .danger {
        color: var(--danger);
      }

      .safe {
        color: var(--success);
      }

      .result-grid {
        display: grid;
        gap: 20px;
        margin-top: 22px;
      }

      .card {
        padding: 18px;
        border-radius: 20px;
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.08);
      }

      .card h2 {
        margin: 0 0 14px;
        font-size: 1.15rem;
      }

      .card ul,
      .card ol {
        margin: 0;
        padding-left: 20px;
        color: var(--muted);
        line-height: 1.75;
      }

      .card code {
        display: inline-block;
        padding: 4px 8px;
        background: rgba(255,255,255,0.08);
        border-radius: 10px;
        color: var(--text);
      }

      @media (max-width: 720px) {
        .hero {
          padding: 20px;
        }

        .search-card,
        .result {
          padding: 20px;
        }
      }
    </style>
  </head>
  <body>
    <div class="page">
      <section class="hero">
        <div class="hero-title">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M10 2a8 8 0 105.293 14.293l4.707 4.707 1.414-1.414-4.707-4.707A8 8 0 0010 2zm0 2a6 6 0 110 12 6 6 0 010-12z" />
          </svg>
          <div>
            <h1>Phishing URL Detector</h1>
            <p>Analyze any URL instantly and save a detailed report with the reason it was flagged as phishing.</p>
          </div>
        </div>

        <div class="search-card">
          <form method="post">
            <div class="input-group">
              <label class="input-label" for="url">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M10.5 3a7.5 7.5 0 105.303 12.803l4.4 4.4 1.414-1.414-4.4-4.4A7.5 7.5 0 0010.5 3zm0 2a5.5 5.5 0 110 11 5.5 5.5 0 010-11z" />
                </svg>
                Enter a URL to inspect
              </label>
              <input id="url" name="url" type="text" placeholder="https://example.com/login" required value="{{ url or '' }}" />
              <button type="submit">Analyze URL</button>
            </div>
          </form>
        </div>
      </section>

      {% if result %}
      <section class="result">
        <div class="result-header">
          <p><strong>URL:</strong> {{ result.url }}</p>
          <p><strong>Prediction:</strong> <span class="status {{ 'danger' if result.prediction == 'phishing' else 'safe' }}">{{ result.prediction }}</span></p>
          <p><strong>Score:</strong> {{ result.score }}</p>
          <p><strong>Report:</strong> saved to <code>{{ result.report_path }}</code></p>
        </div>

        <div class="result-grid">
          <div class="card">
            <h2>Why this result?</h2>
            <ul>
            {% for reason in result.reasons %}
              <li>{{ reason }}</li>
            {% endfor %}
            </ul>
          </div>
          <div class="card">
            <h2>Feature values</h2>
            <ul>
            {% for key, value in result.features.items() %}
              <li><strong>{{ key }}:</strong> {{ value }}</li>
            {% endfor %}
            </ul>
          </div>
          {% if result.importances %}
          <div class="card">
            <h2>Feature importance</h2>
            <ol>
            {% for name, importance in result.importances %}
              <li>{{ name }}: {{ importance|round(3) }}</li>
            {% endfor %}
            </ol>
          </div>
          {% endif %}
        </div>
      </section>
      {% endif %}
    </div>
  </body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            prediction, score, features, importances, reasons = explain_url_prediction(model, url)
            label = "phishing" if prediction == 1 else "legitimate"
            report = build_report(url, prediction, score, features, importances, reasons)
            report_path = save_url_report(report)
            result = {
                "url": url,
                "prediction": label,
                "score": f"{score:.4f}",
                "features": features,
                "importances": importances,
                "reasons": reasons,
                "report_path": str(report_path),
            }

    return render_template_string(TEMPLATE, result=result, url=url)


if __name__ == "__main__":
    app.run(debug=True, port=5000)

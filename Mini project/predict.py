import sys
from pathlib import Path
from src.phishing_detector import explain_url_prediction, load_model, build_report, save_url_report

MODEL_PATH = Path("models/phishing_detector.joblib")


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python predict.py <url>")
        sys.exit(1)

    url = sys.argv[1].strip()
    model = load_model(MODEL_PATH)
    prediction, score, features, importances, reasons = explain_url_prediction(model, url)
    label = "phishing" if prediction == 1 else "legitimate"
    report = build_report(url, prediction, score, features, importances, reasons)
    report_path = save_url_report(report)

    print(f"URL: {url}")
    print(f"Prediction: {label} (score={score:.4f})")
    print("\nReasons:")
    for reason in reasons:
        print(f"- {reason}")

    print("\nFeature values:")
    for name, value in features.items():
        print(f"- {name}: {value}")

    if importances:
        print("\nFeature importances:")
        for name, importance in importances[:8]:
            print(f"- {name}: {importance:.4f}")

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()

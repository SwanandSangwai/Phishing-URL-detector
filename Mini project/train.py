from pathlib import Path
from src.phishing_detector import load_data, train_model

DATA_PATH = Path("data")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "phishing_detector.joblib"


def main() -> None:
    df = load_data(DATA_PATH)
    model = train_model(df)
    model.save(MODEL_PATH)
    print(f"Model trained and saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()

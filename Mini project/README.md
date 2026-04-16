# Phishing URL Detector

A machine learning project to detect phishing URLs using URL feature extraction, explainability, and a web interface.

## Project structure

- `train.py` - trains the model from all CSV files in `data/` and saves the classifier
- `predict.py` - predicts whether a single URL is phishing or legitimate and shows feature-level explainability
- `app.py` - web interface for URL analysis
- `src/phishing_detector.py` - feature extraction, dataset loading, model training, persistence, prediction, and explainability logic
- `data/phishing_urls.csv` - sample dataset with labeled URLs
- `data/phishing_urls_extra.csv` - extended sample dataset to demonstrate loader support for multiple CSVs
- `requirements.txt` - Python dependencies

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Train the model

```bash
python train.py
```

This will create `models/phishing_detector.joblib`.

## Predict a URL from the command line

```bash
python predict.py "http://example.com/login"
```

## Run the web app

```bash
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Scan report storage

Each scanned URL is saved as a JSON report under the `reports/` folder. The report includes prediction, score, extracted features, feature importances, and the reason(s) why a URL was marked phishing.

## Dataset loader

The training script loads all `.csv` files found in the `data/` folder. This lets you expand the dataset by adding new files without changing the code.

## Notes

- This project now includes a web app frontend, an extended dataset loader, more advanced URL features, and prediction explainability.
- Improve detection quality by adding real-world labeled URLs, augmenting the dataset, or experimenting with other classifiers.

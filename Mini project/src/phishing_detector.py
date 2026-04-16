import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

SUSPICIOUS_WORDS = [
    "login",
    "secure",
    "update",
    "verify",
    "account",
    "bank",
    "confirm",
    "webscr",
    "wp-admin",
    "ebayisapi",
    "support",
    "billing",
    "payment",
    "click",
    "verify-email",
]

SUSPICIOUS_TLDS = {"zip", "ru", "xyz", "top", "work", "ml", "cf", "gq", "stream", "download"}

FEATURE_NAMES = [
    "url_length",
    "digit_count",
    "special_character_count",
    "has_ip_address",
    "subdomain_count",
    "host_length",
    "path_length",
    "query_length",
    "path_segment_count",
    "query_parameter_count",
    "has_at_symbol",
    "is_https",
    "suspicious_tld",
    "suspicious_word_count",
    "token_count",
    "digit_ratio",
]


@dataclass
class PhishingModel:
    pipeline: Pipeline

    def save(self, path: Path) -> None:
        joblib.dump(self.pipeline, path)


def load_data(path: Path) -> pd.DataFrame:
    if path.is_dir():
        csv_files = sorted(path.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in directory: {path}")
        frames = [pd.read_csv(csv_path) for csv_path in csv_files]
        df = pd.concat(frames, ignore_index=True)
    else:
        df = pd.read_csv(path)

    df = df.dropna(subset=["url", "label"])
    df = df.drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)
    return df


def has_ip_address(url: str) -> int:
    ip_pattern = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
    return int(bool(ip_pattern.search(url)))


def count_special_chars(url: str) -> int:
    return sum(1 for c in url if c in "@?&=!#$%*~_-+/.\\")


def count_subdomains(host: str) -> int:
    if not host:
        return 0
    parts = host.split(".")
    return max(0, len(parts) - 2)


def suspicious_word_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for word in SUSPICIOUS_WORDS if word in url_lower)


def parse_url(url: str) -> Tuple[str, str, str, str]:
    canonical = url if re.match(r"^[a-zA-Z]+://", url) else f"http://{url}"
    parsed = urlparse(canonical)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()
    return host, path, query, scheme


def extract_features(urls: Iterable[str]) -> List[List[float]]:
    result: List[List[float]] = []
    for url in urls:
        url_lower = url.lower()
        host, path, query, scheme = parse_url(url)
        length = len(url)
        digits = sum(c.isdigit() for c in url)
        specials = count_special_chars(url)
        ip_flag = has_ip_address(url)
        subdomains = count_subdomains(host)
        host_length = len(host)
        path_length = len(path)
        query_length = len(query)
        path_segment_count = len([segment for segment in path.split("/") if segment])
        query_parameter_count = len([param for param in query.split("&") if param]) if query else 0
        has_at = int("@" in url)
        https_flag = int(scheme == "https")
        tld = host.split('.')[-1] if '.' in host else ""
        suspicious_tld = int(tld in SUSPICIOUS_TLDS)
        suspicious = suspicious_word_count(url)
        token_count = len(re.findall(r"[A-Za-z0-9]+", url))
        digit_ratio = digits / (length + 1)

        result.append([
            length,
            digits,
            specials,
            ip_flag,
            subdomains,
            host_length,
            path_length,
            query_length,
            path_segment_count,
            query_parameter_count,
            has_at,
            https_flag,
            suspicious_tld,
            suspicious,
            token_count,
            digit_ratio,
        ])
    return result


def feature_names() -> List[str]:
    return FEATURE_NAMES.copy()


def describe_phishing_reasons(features: Dict[str, Any], score: float, prediction: int) -> List[str]:
    reasons: List[str] = []
    if features.get("has_ip_address"):
        reasons.append("URL contains a raw IP address")
    if features.get("has_at_symbol"):
        reasons.append("URL contains an '@' symbol")
    if features.get("suspicious_word_count", 0) > 0:
        reasons.append("URL contains suspicious words or phrases")
    if features.get("suspicious_tld"):
        reasons.append("URL uses a suspicious top-level domain")
    if features.get("subdomain_count", 0) >= 3:
        reasons.append("URL has many subdomains")
    if features.get("path_length", 0) > 50:
        reasons.append("URL path is unusually long")
    if features.get("query_parameter_count", 0) > 3:
        reasons.append("URL contains many query parameters")
    if features.get("is_https") == 0:
        reasons.append("URL is not using HTTPS")
    if score >= 0.8:
        reasons.append("Model confidence is high for phishing")

    if prediction == 1 and not reasons:
        reasons.append("Model predicted phishing but no explicit heuristic reason was extracted")
    if prediction == 0 and not reasons:
        reasons.append("No strong phishing indicators were detected")
    return reasons


def build_report(url: str, prediction: int, score: float, features: Dict[str, Any], importances: List[Tuple[str, float]], reasons: List[str]) -> Dict[str, Any]:
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": url,
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "score": score,
        "features": features,
        "feature_importances": [{"feature": name, "importance": importance} for name, importance in importances],
        "reasons": reasons,
    }


def save_url_report(report: Dict[str, Any], report_dir: Path = Path("reports")) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    report_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{hashlib.sha1(report['url'].encode('utf-8')).hexdigest()[:8]}.json"
    report_path = report_dir / report_name
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    return report_path


def prepare_features(df: pd.DataFrame) -> Tuple[List[List[float]], List[int]]:
    urls = df["url"].astype(str).tolist()
    features = extract_features(urls)
    labels = df["label"].astype(int).tolist()
    return features, labels


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42)),
    ])


def train_model(df: pd.DataFrame) -> PhishingModel:
    X, y = prepare_features(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)
    print("Training complete. Evaluation on holdout set:")
    print(classification_report(y_test, predictions, digits=4))
    return PhishingModel(pipeline=pipeline)


def load_model(path: Path) -> Pipeline:
    return joblib.load(path)


def predict_url(model: Pipeline, url: str) -> Tuple[int, float]:
    features = extract_features([url])
    score = float(model.predict_proba(features)[0][1])
    prediction = int(model.predict(features)[0])
    return prediction, score


def explain_url_prediction(model: Pipeline, url: str) -> Tuple[int, float, Dict[str, Any], List[Tuple[str, float]], List[str]]:
    raw_features = extract_features([url])[0]
    feature_map = dict(zip(feature_names(), raw_features))
    prediction = int(model.predict([raw_features])[0])
    score = float(model.predict_proba([raw_features])[0][1])
    importances: List[Tuple[str, float]] = []
    classifier = getattr(model, "named_steps", {}).get("classifier")
    if classifier is not None and hasattr(classifier, "feature_importances_"):
        importances = sorted(
            zip(feature_names(), classifier.feature_importances_.tolist()),
            key=lambda item: item[1],
            reverse=True,
        )
    reasons = describe_phishing_reasons(feature_map, score, prediction)
    return prediction, score, feature_map, importances, reasons

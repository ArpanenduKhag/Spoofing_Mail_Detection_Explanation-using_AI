import re
import string
import pickle
import joblib
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from transformers import pipeline
import numpy as np

# --- Load Models Once ---
bilstm_model = load_model("model/phishing_bilstm_model.h5")
gru_model = load_model("model/phishing_gru_model.h5")  # Load GRU model

with open("model/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

legit_model = joblib.load("model/legit_type_classifier.pkl")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# --- Text Cleaning ---
def clean_text(text):
    text = text.lower()
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub(f"[{re.escape(string.punctuation)}]", '', text)
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\w*\d\w*', '', text)
    return text.strip()

# --- Ensemble Prediction with BiLSTM + GRU ---
def predict_with_ensemble(text: str, weight_bilstm: float = 0.5, weight_gru: float = 0.5) -> float:
    """
    Returns phishing probability by averaging BiLSTM and GRU model outputs.
    """
    cleaned = clean_text(text)
    seq = tokenizer.texts_to_sequences([cleaned])
    padded = pad_sequences(seq, maxlen=200, padding='post', truncating='post')

    pred_bilstm = bilstm_model.predict(padded)[0][0]
    pred_gru = gru_model.predict(padded)[0][0]

    # Weighted average
    final_pred = (weight_bilstm * pred_bilstm) + (weight_gru * pred_gru)
    return float(final_pred)

# --- Summarize Body Content ---
def summarize_text(text: str) -> str:
    if len(text.strip()) < 50:
        return text.strip()
    try:
        summary = summarizer(text, max_length=100, min_length=30, do_sample=False)[0]['summary_text']
        return summary.strip()
    except Exception:
        return text.strip()

# --- Predict Legitimate Email Type (Job-related, Transactional, etc.) ---
def classify_legit_type(text: str) -> str:
    try:
        return legit_model.predict([clean_text(text)])[0]
    except Exception:
        return "unknown"

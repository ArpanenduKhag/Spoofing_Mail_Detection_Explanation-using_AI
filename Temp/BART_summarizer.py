import os
from tqdm import tqdm
from transformers import BartTokenizer, BartForConditionalGeneration
import torch

# --- CONFIG ---
input_folder = "all_text_files"  # 📂 Folder with original text files
output_folder = "summarized_text_files"  # 📂 Output folder (set this dynamically if needed)
os.makedirs(output_folder, exist_ok=True)

# --- Load BART model ---
tokenizer = BartTokenizer.from_pretrained("facebook/bart-large-cnn")
model = BartForConditionalGeneration.from_pretrained("facebook/bart-large-cnn")
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = model.to(device)

# --- Chunking utility ---
def split_into_chunks(text, max_tokens=1024, stride=512):
    tokens = tokenizer.encode(text, truncation=False)
    chunks = []
    start = 0
    while start < len(tokens):
        end = min(start + max_tokens, len(tokens))
        chunk = tokens[start:end]
        chunks.append(chunk)
        start += stride
    return chunks

# --- Summarization utility ---
def summarize_text(text):
    if not text.strip():
        return "[Empty file]"

    token_chunks = split_into_chunks(text, max_tokens=1024, stride=800)
    partial_summaries = []

    for chunk in token_chunks:
        input_tensor = torch.tensor([chunk]).to(device)
        summary_ids = model.generate(
            input_tensor,
            max_length=150,
            min_length=40,
            length_penalty=2.0,
            num_beams=4,
            early_stopping=True
        )
        summary = tokenizer.decode(summary_ids[0], skip_special_tokens=True)
        partial_summaries.append(summary)

    # Combine all partial summaries
    combined_summary = " ".join(partial_summaries)

    # Final summary pass to compress combined summary
    inputs = tokenizer.encode(combined_summary, return_tensors="pt", max_length=1024, truncation=True).to(device)
    final_ids = model.generate(
        inputs,
        max_length=180,
        min_length=60,
        length_penalty=2.0,
        num_beams=4,
        early_stopping=True
    )
    final_summary = tokenizer.decode(final_ids[0], skip_special_tokens=True)
    return final_summary

# --- Process All Files ---
text_files = [f for f in os.listdir(input_folder) if f.lower().endswith(".txt")]
print(f"📁 Found {len(text_files)} text files to summarize.\n")

for filename in tqdm(text_files, desc="Summarizing files"):
    input_path = os.path.join(input_folder, filename)
    output_path = os.path.join(output_folder, filename)

    try:
        with open(input_path, "r", encoding="utf-8") as file:
            text = file.read()

        summary = summarize_text(text)

        with open(output_path, "w", encoding="utf-8") as file:
            file.write(summary)

    except Exception as e:
        print(f"❌ Error in {filename}: {e}")

print(f"\n✅ All summaries saved in: {output_folder}")

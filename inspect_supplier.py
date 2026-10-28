
import pymupdf
from pathlib import Path

pdf_path = Path("833154215-SLM-4300 NSV-30.07.2026.pdf")

if not pdf_path.exists():
    print(f"PDF not found: {pdf_path.resolve()}")
    raise SystemExit(1)

with pymupdf.open(pdf_path) as doc:
    for page_number, page in enumerate(doc, start=1):
        print(f"\n--- PAGE {page_number} ---")
        print(page.get_text("text", sort=True))

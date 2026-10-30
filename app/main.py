from __future__ import annotations

import os
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import hashlib
import io
import os
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import pymupdf
import pytesseract
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from PIL import Image
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from app.auth import router as auth_router, get_current_admin

load_dotenv()


pytesseract.pytesseract.tesseract_cmd = os.getenv(
    "TESSERACT_CMD",
    "tesseract",
)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB = os.getenv("MONGODB_DB", "invoice_verification")

_mongo_client: AsyncIOMotorClient | None = None


def get_db():
    return _mongo_client[MONGODB_DB]


app = FastAPI(
    title="Machine Invoice Verification",
    description=(
        "Compare a supplier machine invoice against "
        "the corresponding customer invoice."
    ),
    version="0.2.0",
)

app.include_router(auth_router)


@app.on_event("startup")
async def startup():
    global _mongo_client
    _mongo_client = AsyncIOMotorClient(MONGODB_URI, tz_aware=True)
    app.state.db = _mongo_client[MONGODB_DB]
    await app.state.db["sessions"].create_index("expires_at", expireAfterSeconds=0)
    await app.state.db["users"].create_index("email", unique=True)
    await app.state.db["sessions"].create_index("token_hash", unique=True)


@app.on_event("shutdown")
async def shutdown():
    if _mongo_client:
        _mongo_client.close()

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_PAGES = 100


def extract_document(data: bytes) -> dict[str, Any]:
    """Extract text page by page, using OCR for image-only pages."""
    try:
        with pymupdf.open(stream=data, filetype="pdf") as document:
            if document.is_encrypted:
                raise HTTPException(
                    status_code=400,
                    detail="Password-protected PDFs are not supported.",
                )

            if not document:
                raise HTTPException(
                    status_code=400,
                    detail="The PDF contains no pages.",
                )

            if len(document) > MAX_PAGES:
                raise HTTPException(
                    status_code=413,
                    detail=f"PDF exceeds the {MAX_PAGES}-page limit.",
                )

            pages = []
            ocr_used = False

            for page_number, page in enumerate(document, start=1):
                text = page.get_text("text").strip()

                if len(text) < 20:
                    try:
                        pixmap = page.get_pixmap(
                            matrix=pymupdf.Matrix(2, 2),
                            alpha=False,
                        )
                        image = Image.open(
                            io.BytesIO(pixmap.tobytes("png"))
                        )
                        text = pytesseract.image_to_string(
                            image, lang="eng"
                        ).strip()
                        ocr_used = True
                    except pytesseract.TesseractNotFoundError as exc:
                        raise HTTPException(
                            status_code=500,
                            detail="Tesseract OCR could not be found.",
                        ) from exc

                pages.append({
                    "page": page_number,
                    "text": text,
                })

            return {
                "pages": pages,
                "page_count": len(document),
                "ocr_used": ocr_used,
            }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Unable to read the uploaded PDF.",
        ) from exc


def clean_identifier(value: str) -> str:
    """Normalize spacing and punctuation without removing ID characters."""
    value = value.strip().strip(" \t:;,.")
    value = re.sub(r"\s+", "", value)
    return value.upper()


def find_first(
    pages: list[dict[str, Any]],
    patterns: list[str],
    group: int = 1,
) -> dict[str, Any] | None:
    """Search page text in reading order and preserve its page number."""
    for page in pages:
        for pattern in patterns:
            match = re.search(
                pattern,
                page["text"],
                flags=re.IGNORECASE | re.MULTILINE,
            )
            if match:
                value = match.group(group).strip()
                if value:
                    return {
                        "value": value,
                        "page": page["page"],
                    }
    return None




def extract_supplier_fields(
    pages: list[dict[str, Any]],
) -> dict[str, Any]:
    """Extract supplier invoice details and machine identifiers."""

    fields = {
        "supplier_invoice_no": find_first(
            pages,
            [
                r"Tax\s*Inv\s*No\.?\s*/\s*SAP\s*Doc\s*No\.?\s*(\d{9})",
                r"Supplier\s+Invoice\s+No\.?\s*[:.]?\s*(\d{6,})",
                r"Invoice\s+No\.?\s*[:.]?\s*(\d{6,})",
            ],
        ),

        "buyer_order_no": find_first(
            pages,
            [
                r"Buyer's\s+Order\s+No\.?\s*[:.]?\s*"
                r"([A-Z0-9]+(?:\s*/\s*[A-Z0-9-]+)+)"
            ],
        ),

        "chassis_no": find_first(
            pages,
            [
                r"Chassis\s+No\.?\s*[-:]?\s*"
                r"([A-Z0-9][A-Z0-9/-]+)"
            ],
        ),

        "engine_no": find_first(
            pages,
            [
                r"Engine\s+No\.?\s*[-:]?\s*"
                r"([A-Z0-9][A-Z0-9/-]+)"
            ],
        ),

        "eml_no": find_first(
            pages,
            [
                r"EML\s+No\.?\s*[-:]?\s*"
                r"([0-9]+(?:\.[0-9]+)?)"
            ],
        ),

        "serial_no": find_first(
            pages,
            [
                r"MFG\s+SL\s+No\.?\s*[-:]?\s*"
                r"([A-Z0-9/-]+)"
            ],
        ),


        # Prefer the model in the invoice item description.
        # Fall back to the remarks' Model field if unavailable.
        "machine_model": (
            find_first(
                pages,
                [
                    # Capture the item description after the machine name
                    # and stop before the 8-digit HSN/SAC code.
                    r"(?im)Self-load\.?\s*Conc\.?\s*Mixer\s+"
                    r"(.+?)\s+\d{8}\b",
                ],
            )
            or find_first(
                pages,
                [
                    r"(?im)\bModel\s*[-:]?\s*([^\r\n]+)"
                ],
            )
        ),

    }

    # Normalize whitespace in the buyer order number while preserving
    # its original page reference.
    order = fields["buyer_order_no"]
    if order:
        order["value"] = re.sub(r"\s+", "", order["value"])

    return fields


def extract_customer_fields(
    pages: list[dict[str, Any]],
) -> dict[str, Any]:
    """Extract customer invoice and machine details."""
    fields = {
        "customer_invoice_no": find_first(
            pages,
            [
                r"Invoice\s+No\.?\s*(?:e-Way\s+Bill\s+No\.?)?"
                r"\s*[\r\n]+\s*([A-Z0-9][A-Z0-9/_-]*)",
            ],
        ),
        "supplier_invoice_reference": find_first(
            pages,
            [
                r"Ref\s+No\.?\s*[-:]?\s*"
                r"([0-9]{6,})",
                r"Reference\s+No\.?\s*&?\s*Date\.?"
                r"\s*[\r\n]+\s*([0-9]{6,})",
            ],
        ),
        "buyer_order_no": find_first(
            pages,
            [
                r"Buyer['’]s\s+Order\s+No\.?\s*"
                r"[\r\n]*\s*([A-Z0-9][A-Z0-9/_-]*)",
            ],
        ),
        "chassis_no": find_first(
            pages,
            [
                r"Chasis\s+No\.?\s*[-:]?\s*"
                r"([A-Z0-9][A-Z0-9/-]*)",
                r"Chassis\s+No\.?\s*[-:]?\s*"
                r"([A-Z0-9][A-Z0-9/-]*)",
            ],
        ),
        "engine_no": find_first(
            pages,
            [
                r"Engine\s+No\.?\s*[-:]?\s*"
                r"([A-Z0-9][A-Z0-9/-]*)",
            ],
        ),
        "machine_model": find_first(
            pages,
            [
                r"\bModel\s*[-:]?\s*"
                r"([^\r\n]+)"
            ],
        ),
    }

    # Customer invoices may combine EML and serial number in one field.
    combined = find_first(
        pages,
        [
            r"EML\s+NO\s*/\s*SL\s+NO\.?\s*[-:]?\s*"
            r"([0-9]+(?:\.[0-9]+)?\s*/\s*[0-9]+)"
        ],
    )

    if combined:
        parts = [
            part.strip()
            for part in combined["value"].split("/", 1)
        ]
        fields["eml_no"] = {
            "value": parts[0],
            "page": combined["page"],
        }
        fields["serial_no"] = {
            "value": parts[1],
            "page": combined["page"],
        }
    else:
        fields["eml_no"] = None
        fields["serial_no"] = None

    # Do not confuse the customer's invoice number with the
    # supplier's invoice number. They serve different purposes.
    return fields


def compare_values(
    field: str,
    supplier: dict[str, Any] | None,
    customer: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare one mapped field and report missing or uncertain values."""
    result = {
        "field": field,
        "supplier": supplier,
        "customer": customer,
        "status": "needs_review",
        "reason": None,
    }

    if not supplier and not customer:
        result["status"] = "missing_both"
        result["reason"] = "Field was not found in either PDF."
        return result

    if not supplier:
        result["status"] = "missing_supplier"
        result["reason"] = "Field was not found in the supplier invoice."
        return result

    if not customer:
        result["status"] = "missing_customer"
        result["reason"] = "Field was not found in the customer invoice."
        return result

    left = supplier["value"]
    right = customer["value"]

    if field == "machine_model":
        # Model descriptions may contain harmless wording differences.
        left_normalized = re.sub(
            r"[^A-Z0-9]", "", left.upper()
        )
        right_normalized = re.sub(
            r"[^A-Z0-9]", "", right.upper()
        )

        if left_normalized == right_normalized:
            result["status"] = "match"
        else:
            result["status"] = "needs_review"
            result["reason"] = (
                "Model descriptions differ; confirm whether "
                "the difference is acceptable."
            )
        return result

    left_normalized = clean_identifier(left)
    right_normalized = clean_identifier(right)

    # Numeric EML identifiers may contain a formatting-only .00 suffix.
    if field == "eml_no":
        try:
            left_normalized = str(Decimal(left_normalized))
            right_normalized = str(Decimal(right_normalized))
        except Exception:
            pass

    if left_normalized == right_normalized:
        result["status"] = "match"
    else:
        result["status"] = "mismatch"
        result["reason"] = "The identifiers differ."

    return result


async def read_pdf(file: UploadFile) -> bytes:
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Upload a PDF file.")

    data = await file.read(MAX_FILE_BYTES + 1)
    await file.close()

    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Each PDF must be 10 MB or smaller.",
        )

    if not data.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="Invalid PDF file.")

    return data


@app.get("/health")
def health():
    return {"status": "ok", "service": "machine-invoice-verification"}


@app.get("/reports")
async def list_reports(skip: int = 0, limit: int = 50, admin=Depends(get_current_admin)):
    cursor = get_db()["reports"].find(
        {},
        {
            "supplier_pdf.filename": 1,
            "customer_pdf.filename": 1,
            "customer_pdf.customer_invoice_no": 1,
            "summary": 1,
            "created_at": 1,
        },
    ).sort("created_at", -1).skip(skip).limit(limit)
    reports = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        reports.append(doc)
    return {"reports": reports, "skip": skip, "limit": limit}


@app.get("/reports/{report_id}")
async def get_report(report_id: str, admin=Depends(get_current_admin)):
    from bson import ObjectId
    try:
        oid = ObjectId(report_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid report ID.")
    doc = await get_db()["reports"].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Report not found.")
    doc["_id"] = str(doc["_id"])
    return doc


@app.post("/compare")
async def compare_pdfs(
    pdf1: UploadFile = File(..., description="Supplier invoice PDF"),
    pdf2: UploadFile = File(..., description="Customer invoice PDF"),
    admin=Depends(get_current_admin),
):
    supplier_data = await read_pdf(pdf1)
    customer_data = await read_pdf(pdf2)

    if hashlib.sha256(supplier_data).hexdigest() == hashlib.sha256(customer_data).hexdigest():
        raise HTTPException(
            status_code=400,
            detail=(
                "Both uploaded documents are the same invoice. "
                "Please upload the supplier invoice and customer invoice separately."
            ),
        )

    supplier_document = extract_document(supplier_data)
    customer_document = extract_document(customer_data)

    supplier_fields = extract_supplier_fields(
        supplier_document["pages"]
    )
    customer_fields = extract_customer_fields(
        customer_document["pages"]
    )

    # Match only equivalent fields across the two documents.
    field_mapping = [
        (
            "supplier_invoice_reference",
            supplier_fields.get("supplier_invoice_no"),
            customer_fields.get("supplier_invoice_reference"),
        ),
        (
            "buyer_order_no",
            supplier_fields.get("buyer_order_no"),
            customer_fields.get("buyer_order_no"),
        ),
        (
            "chassis_no",
            supplier_fields.get("chassis_no"),
            customer_fields.get("chassis_no"),
        ),
        (
            "engine_no",
            supplier_fields.get("engine_no"),
            customer_fields.get("engine_no"),
        ),
        (
            "eml_no",
            supplier_fields.get("eml_no"),
            customer_fields.get("eml_no"),
        ),
        (
            "serial_no",
            supplier_fields.get("serial_no"),
            customer_fields.get("serial_no"),
        ),
        (
            "machine_model",
            supplier_fields.get("machine_model"),
            customer_fields.get("machine_model"),
        ),
    ]

    results = [
        compare_values(name, supplier, customer)
        for name, supplier, customer in field_mapping
    ]

    summary = {
        status: sum(
            1 for item in results if item["status"] == status
        )
        for status in (
            "match",
            "mismatch",
            "needs_review",
            "missing_supplier",
            "missing_customer",
            "missing_both",
        )
    }

    report = {
        "supplier_pdf": {
            "filename": pdf1.filename,
            "page_count": supplier_document["page_count"],
            "ocr_used": supplier_document["ocr_used"],
            "fields": supplier_fields,
        },
        "customer_pdf": {
            "filename": pdf2.filename,
            "page_count": customer_document["page_count"],
            "ocr_used": customer_document["ocr_used"],
            "fields": customer_fields,
            "customer_invoice_no": customer_fields.get(
                "customer_invoice_no"
            ),
        },
        "summary": summary,
        "results": results,
        "created_at": datetime.now(timezone.utc),
    }

    try:
        await get_db()["reports"].insert_one(report)
    except Exception as exc:
        print(f"Failed to save comparison report: {exc}")
        raise HTTPException(
            status_code=503,
            detail="The comparison was processed, but the report could not be saved. Please try again.",
        ) from exc

    report.pop("_id", None)
    return report

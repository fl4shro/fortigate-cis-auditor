"""
PDF Report Generator
=====================
Generates real PDF reports using WeasyPrint.
"""

import logging

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """Generate PDF compliance reports."""

    def __init__(self):
        self._weasyprint_available = False

        try:
            import weasyprint
            self._weasyprint_available = True
        except ImportError as e:
            logger.error(f"WeasyPrint is not available: {e}")

    @property
    def is_available(self) -> bool:
        return self._weasyprint_available

    def generate(self, html_content: str, output_path) -> bool:
        """
        Generate a real PDF from HTML content.

        ``output_path`` may be either a filesystem path or a
        file-like object such as io.BytesIO.

        Returns:
            True if the PDF was successfully generated.

        Raises:
            RuntimeError if WeasyPrint is unavailable or PDF
            generation fails.
        """

        if not self._weasyprint_available:
            raise RuntimeError(
                "WeasyPrint is not available. "
                "PDF generation cannot continue."
            )

        try:
            import weasyprint

            html_doc = weasyprint.HTML(
                string=html_content
            )

            html_doc.write_pdf(output_path)

            if hasattr(output_path, "seek"):
                output_path.seek(0)

            logger.info("PDF report generated successfully.")

            return True

        except Exception as e:
            logger.exception(
                f"PDF generation failed: {e}"
            )

            raise RuntimeError(
                f"Falha ao gerar o PDF: {e}"
            ) from e

import qrcode
import io
import base64
import hmac
import hashlib
import json
from app.core.config import settings

class QRService:
    @staticmethod
    def generate_signed_payload(data: dict) -> str:
        """
        Generates the payload string. Signs it if in Secure mode
        To ensure robust verification, the inner data is stringified first
        Structure: { "data_str": "{...json...}", "sig": "..." }
        """
        data_str = json.dumps(data, separators=(',', ':'))

        # Encrypts the data_str using SECRET_KEY
        if settings.use_signed_qr:
            signature = hmac.new(
                settings.SECRET_KEY.encode(),
                data_str.encode(),
                hashlib.sha256
            ).hexdigest()
            # Return a wrapper containing the stringified data and signature
            return json.dumps({"data_str": data_str, "sig": signature})

        # Return the insecure data string directly
        return data_str

    @staticmethod
    def create_qr_image(data_str: str) -> str:
        """
        Creates a QR code image and returns it as a base64 string
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data_str)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return img_str

    @staticmethod
    def verify_qr_payload(payload_str: str) -> dict | None:
        """
        Parses and verifies the QR payload
        Returns the data dict if valid, None otherwise
        """
        try:
            if settings.use_signed_qr:
                wrapper = json.loads(payload_str)
                data_str = wrapper.get("data_str")
                sig = wrapper.get("sig")

                if not data_str or not sig:
                    return None

                # Verify signature on the exact string received
                expected_sig = hmac.new(
                    settings.SECRET_KEY.encode(),
                    data_str.encode(),
                    hashlib.sha256
                ).hexdigest()

                if hmac.compare_digest(sig, expected_sig):
                    return json.loads(data_str)
                return None
            else:
                # Insecure: payload_str is just the JSON data
                return json.loads(payload_str)
        except Exception:
            return None

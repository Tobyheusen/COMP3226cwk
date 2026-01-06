import json
import base64
import logging
from jwcrypto import jwk, jws
from jwcrypto.common import json_decode

logger = logging.getLogger(__name__)

class CryptoUtils:
    @staticmethod
    def verify_raw_signature(jwk_dict: dict, data: str, signature_b64: str) -> bool:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            # logger.info(f"Verifying signature for data: {data}")
            # logger.info(f"JWK: {json.dumps(jwk_dict)}")

            # Load key from JWK using jwcrypto to handle parsing
            key = jwk.JWK(**jwk_dict)

            sig_bytes = base64.b64decode(signature_b64)
            data_bytes = data.encode('utf-8')

            # Get the internal cryptography key
            ktype = key.get_op_key('verify')

            if isinstance(ktype, rsa.RSAPublicKey):
                # Check alg in JWK
                alg = jwk_dict.get('alg')
                logger.info(f"JWK alg: {alg}")

                if alg == 'RS256' or alg is None:
                     try:
                        ktype.verify(
                            sig_bytes,
                            data_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        # logger.info("Verified with RS256")
                        return True
                     except Exception as e:
                        # logger.error(f"RS256 Verify failed: {e}")
                        return False

                elif alg == 'PS256':
                     ktype.verify(
                        sig_bytes,
                        data_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                     return True
                else:
                    logger.error(f"Unsupported RSA alg: {alg}")
                    return False

            elif isinstance(ktype, ec.EllipticCurvePublicKey):
                ktype.verify(
                    sig_bytes,
                    data_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                return True

            return False

        except Exception as e:
            import traceback
            logger.error(f"Signature verification failed with exception: {type(e).__name__}: {e}")
            return False

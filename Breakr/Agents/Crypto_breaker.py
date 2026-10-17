from pathlib import Path
import re

from Agents.base_breaker import (
    BaseBreaker,
    CODE_EXTENSIONS,
    COMPONENT_EXTENSIONS,
    JS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    LineIndex,
    Rule,
    clip,
    strip_comments,
)


JS = frozenset(JS_EXTENSIONS | COMPONENT_EXTENSIONS)
PY = frozenset(PYTHON_EXTENSIONS)
JS_PY = frozenset(JS | PY)

SECURITY_VALUE = (
    r"(?=[^\n]*(?:token|secret|passw|otp|nonce|salt|session|reset|api_?key|"
    r"csrf|verif|invite|coupon|voucher|\bcode\b|\bpin\b))"
)

STRING_LITERAL = re.compile(r"([\"'])([^\"']{3,})\1")

MIN_PBKDF2_ITERATIONS = 100_000

WEAK_CIPHER = dict(
    severity="MEDIUM",
    explanation=(
        "This cipher or mode is broken or leaks patterns in the data (ECB "
        "encrypts identical blocks to identical output). Encrypted data "
        "may be readable or forgeable."
    ),
    recommendation=(
        "Use AES-256-GCM or ChaCha20-Poly1305 with a random nonce per "
        "message, or a high-level library (libsodium, Fernet)."
    ),
    cwe="CWE-327",
)

RULES = [

    # -------------------------
    # Password hashing
    # -------------------------

    Rule(
        title="Password hashed with a fast hash (MD5/SHA)",
        pattern=(
            r"hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\([^\n]*pass"
            r"|pass\w*\s*=\s*hashlib\.\w+\("
            r"|createHash\([^)]*\)[^\n]*update\([^)]*pass"
            r"|CryptoJS\.(?:MD5|SHA1|SHA256|SHA512)\([^)]*pass"
            r"|\bmd5\([^)]*pass"
        ),
        severity="HIGH",
        confidence=0.75,
        explanation=(
            "General-purpose hashes are designed to be fast, so leaked "
            "password hashes can be cracked at billions of guesses per "
            "second on a GPU."
        ),
        recommendation=(
            "Hash passwords with Argon2id, bcrypt or scrypt (e.g. argon2-cffi, "
            "bcrypt, passlib; or your auth provider) with a per-user salt."
        ),
        cwe="CWE-916",
        extensions=JS_PY,
    ),
    Rule(
        title="Weak hash algorithm (MD5/SHA1)",
        pattern=(
            r"hashlib\.(?:md5|sha1)\(|hashlib\.new\(\s*[\"'](?:md5|sha1)[\"']"
            r"|createHash\(\s*[\"'](?:md5|sha1)[\"']|CryptoJS\.(?:MD5|SHA1)\("
        ),
        severity="LOW",
        confidence=0.45,
        explanation=(
            "MD5 and SHA1 have practical collision attacks. They are fine for "
            "cache keys and checksums but not for signatures, integrity "
            "checks against attackers, or anything security related."
        ),
        recommendation="Use SHA-256 or better for integrity, and HMAC-SHA256 for signatures.",
        cwe="CWE-328",
        extensions=JS_PY,
        exclude=r"pass|usedforsecurity\s*=\s*False|etag|checksum|cache|fingerprint|gravatar",
    ),
    Rule(
        title="Low bcrypt cost factor",
        code_only=True,
        pattern=(
            r"gensalt\(\s*(?:rounds\s*=\s*)?[1-9]\s*\)"
            r"|bcrypt\w*\.hash(?:Sync)?\([^,\n]+,\s*[1-9]\s*[,)]"
            r"|genSalt(?:Sync)?\(\s*[1-9]\s*[,)]"
        ),
        severity="LOW",
        confidence=0.7,
        explanation="A bcrypt cost below 10 makes password hashes much cheaper to crack.",
        recommendation="Use a cost factor of at least 12.",
        cwe="CWE-916",
        extensions=JS_PY,
    ),
    Rule(
        title="Low PBKDF2 iteration count",
        pattern=(
            r"pbkdf2_hmac\(\s*[^,]+,[^,]+,[^,]+,\s*(?:iterations\s*=\s*)?(?P<iterations>\d[\d_]*)"
            r"|pbkdf2(?:Sync)?\(\s*[^,]+,[^,]+,\s*(?P<iterations2>\d[\d_]*)"
            r"|PBKDF2HMAC\([^)]*iterations\s*=\s*(?P<iterations3>\d[\d_]*)"
        ),
        severity="MEDIUM",
        confidence=0.75,
        explanation="Too few PBKDF2 iterations make derived keys and password hashes cheap to brute-force.",
        recommendation="Use at least 600,000 iterations for PBKDF2-HMAC-SHA256, or switch to Argon2id.",
        cwe="CWE-916",
        extensions=JS_PY,
    ),
    Rule(
        title="Passwords compared in plaintext",
        pattern=(
            r"(?:\.|\[[\"'])password[\"']?\]?\s*(?:===?|!==?)\s*"
            r"(?:req|request|body|data|input|form|params|credentials)[\w.\[\]\"']*password"
            r"|(?:req|request|body|data|input|form|params|credentials)[\w.\[\]\"']*password[\"']?\]?\s*"
            r"(?:===?|!==?)\s*\w+(?:\.|\[[\"'])password\b"
        ),
        severity="HIGH",
        confidence=0.6,
        explanation=(
            "The submitted password is compared directly with a stored "
            "value, which means passwords are stored in plaintext (or the "
            "comparison bypasses the hash)."
        ),
        recommendation=(
            "Store only salted password hashes and compare with "
            "bcrypt.compare / argon2.verify / check_password_hash."
        ),
        cwe="CWE-256",
        extensions=JS_PY,
    ),

    # -------------------------
    # Randomness
    # -------------------------

    Rule(
        title="Insecure randomness for a security value",
        pattern=r"^" + SECURITY_VALUE + r"[^\n]*\bMath\.random\(",
        severity="MEDIUM",
        confidence=0.65,
        explanation=(
            "Math.random() is predictable. Tokens, OTPs, reset codes or IDs "
            "generated with it can be guessed by an attacker."
        ),
        recommendation="Use crypto.randomBytes / crypto.randomUUID / crypto.getRandomValues.",
        cwe="CWE-338",
        extensions=JS,
    ),
    Rule(
        title="Insecure randomness for a security value",
        pattern=(
            r"^" + SECURITY_VALUE
            + r"[^\n]*\brandom\.(?:random|randint|choice|choices|randrange|getrandbits|sample)\("
        ),
        severity="MEDIUM",
        confidence=0.65,
        explanation=(
            "Python's random module is predictable. Tokens, OTPs or reset "
            "codes generated with it can be guessed by an attacker."
        ),
        recommendation="Use the secrets module (secrets.token_urlsafe, secrets.randbelow).",
        cwe="CWE-338",
        extensions=PY,
    ),

    # -------------------------
    # JWT
    # -------------------------

    Rule(
        title="JWT 'none' algorithm accepted",
        pattern=r"algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']",
        severity="CRITICAL",
        confidence=0.85,
        explanation="Accepting alg 'none' means anyone can forge a token without a signature.",
        recommendation="Pin the expected algorithm, e.g. algorithms=['HS256'] or ['RS256'].",
        cwe="CWE-347",
        extensions=JS_PY,
    ),
    Rule(
        title="JWT signature verification disabled",
        pattern=(
            r"jwt\.decode\([^)]*(?:verify\s*=\s*False|[\"']verify_signature[\"']\s*:\s*False)"
        ),
        severity="HIGH",
        confidence=0.85,
        explanation="Tokens are decoded without checking the signature, so any user can forge claims (e.g. role: admin).",
        recommendation="Always verify the signature and pin the algorithm when decoding tokens.",
        cwe="CWE-347",
        extensions=PY,
    ),
    Rule(
        title="JWT expiry ignored",
        pattern=r"ignoreExpiration\s*:\s*true|[\"']verify_exp[\"']\s*:\s*False",
        severity="MEDIUM",
        confidence=0.8,
        explanation="Expired tokens are still accepted, so stolen tokens work forever.",
        recommendation="Remove the override and keep token lifetimes short.",
        cwe="CWE-613",
        extensions=JS_PY,
    ),
    Rule(
        title="Hardcoded JWT signing secret",
        pattern=(
            r"jwt\.(?:sign|verify)\(\s*[^,\n]+,\s*[\"'][^\"'\n]+[\"']"
            r"|jwt\.(?:encode|decode)\(\s*[^,\n]+,\s*[\"'][^\"'\n]+[\"']"
        ),
        severity="HIGH",
        confidence=0.8,
        explanation=(
            "The token signing key is in the source code. Anyone who reads "
            "the code can mint valid tokens for any user."
        ),
        recommendation="Load a long random signing key from an environment variable or secret manager, and rotate it.",
        cwe="CWE-321",
        extensions=JS_PY,
    ),

    # -------------------------
    # Ciphers
    # -------------------------

    Rule(
        title="Broken cipher (DES/3DES/RC4/Blowfish)",
        pattern=(
            r"\b(?:DES|DES3|ARC4|ARC2|Blowfish|CAST)\.new\("
            r"|algorithms\.(?:TripleDES|Blowfish|ARC4|IDEA|CAST5)\("
            r"|createCipheriv\(\s*[\"'](?:des|des-ede3|des3|rc4|rc2|bf|blowfish)[\w-]*[\"']"
        ),
        confidence=0.8,
        extensions=JS_PY,
        **WEAK_CIPHER,
    ),
    Rule(
        title="ECB cipher mode",
        pattern=r"\bMODE_ECB\b|\bmodes\.ECB\(",
        confidence=0.8,
        extensions=PY,
        code_only=True,
        **WEAK_CIPHER,
    ),
    Rule(
        title="ECB cipher mode",
        pattern=r"[\"']aes-\d+-ecb[\"']|[\"']AES/ECB",
        confidence=0.8,
        extensions=JS_PY,
        **WEAK_CIPHER,
    ),
    Rule(
        title="Deprecated crypto.createCipher (no IV)",
        pattern=r"\bcreateCipher\(",
        confidence=0.8,
        extensions=JS,
        **WEAK_CIPHER,
    ),
    Rule(
        title="Hardcoded encryption key or IV",
        pattern=(
            r"createCipheriv\(\s*[^,]+,\s*[\"'][^\"']+[\"']"
            r"|\b(?:iv|IV|nonce)\s*[:=]\s*b?[\"'][^\"']{8,}[\"']"
            r"|AES\.new\(\s*b?[\"'][^\"']+[\"']"
            r"|Fernet\(\s*b?[\"'][^\"']+[\"']"
        ),
        severity="HIGH",
        confidence=0.65,
        explanation=(
            "A fixed key or IV in the source means anyone with the code can "
            "decrypt the data, and reusing an IV breaks GCM/CTR encryption."
        ),
        recommendation="Load keys from a secret manager and generate a fresh random IV/nonce for every encryption.",
        cwe="CWE-321",
        extensions=JS_PY,
        ignore_case=False,
    ),

    # -------------------------
    # TLS / keys
    # -------------------------

    Rule(
        title="Outdated TLS/SSL protocol version",
        pattern=(
            r"ssl\.PROTOCOL_(?:SSLv2|SSLv3|TLSv1|TLSv1_1)\b"
            r"|secureProtocol\s*:\s*[\"'](?:SSLv2|SSLv3|TLSv1|TLSv1_1)_method"
            r"|minVersion\s*:\s*[\"']TLSv1(?:\.1)?[\"']"
        ),
        severity="MEDIUM",
        confidence=0.8,
        explanation="SSLv3, TLS 1.0 and TLS 1.1 have known attacks and are deprecated.",
        recommendation="Require TLS 1.2 or newer.",
        cwe="CWE-326",
        extensions=JS_PY,
    ),
    Rule(
        title="Weak RSA key size",
        code_only=True,
        pattern=r"key_size\s*=\s*(?:512|768|1024)\b|modulusLength\s*:\s*(?:512|768|1024)\b",
        severity="MEDIUM",
        confidence=0.85,
        explanation="RSA keys under 2048 bits can be factored with modest resources.",
        recommendation="Use RSA 3072+ or an elliptic-curve key (Ed25519, P-256).",
        cwe="CWE-326",
        extensions=JS_PY,
    ),
]

JWT_DECODE = re.compile(r"\bjwt\.decode\(")
JWT_VERIFY = re.compile(r"\bjwt\.verify\(|jwtVerify\(")


class CryptoBreaker(BaseBreaker):

    name = "CryptoBreaker"
    description = (
        "Weak password hashing, MD5/SHA1, Math.random tokens, JWT 'none' / "
        "unverified / hardcoded secrets, broken ciphers, ECB, static IVs"
    )
    prompt_file = "Crypto.txt"
    always_run = True
    extensions = CODE_EXTENSIONS

    def refine(self, finding, rule, match, code):

        if rule.title == "Low PBKDF2 iteration count":

            raw = (
                match.group("iterations")
                or match.group("iterations2")
                or match.group("iterations3")
            )

            if int(raw.replace("_", "")) >= MIN_PBKDF2_ITERATIONS:
                return None

        if rule.cwe == "CWE-321":
            finding.evidence = STRING_LITERAL.sub(
                lambda m: m.group(1) + m.group(2)[:3] + "***" + m.group(1),
                finding.evidence,
            )

        return finding

    def scan_file(self, file_path: Path, content: str):

        code = strip_comments(content, file_path)
        findings = self.scan_rules(file_path, content, RULES, code)

        # jsonwebtoken's jwt.decode() never checks the signature.
        if file_path.suffix.lower() in JS_EXTENSIONS:

            decode = JWT_DECODE.search(code)

            if decode and not JWT_VERIFY.search(code):

                index = LineIndex(content)
                line = index.line_of(decode.start())

                findings.append(
                    self.make_finding(
                        title="JWT decoded without signature verification",
                        severity="MEDIUM",
                        confidence=0.55,
                        file=self.relative(file_path),
                        line=line,
                        evidence=clip(index.text(line)),
                        explanation=(
                            "jwt.decode() only base64-decodes the token; it "
                            "does not check the signature. If these claims "
                            "are trusted for auth, anyone can forge them."
                        ),
                        recommendation="Use jwt.verify(token, secret, { algorithms: [...] }) before trusting claims.",
                        cwe="CWE-347",
                    )
                )

        return findings


if __name__ == "__main__":
    CryptoBreaker.cli()

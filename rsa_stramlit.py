import streamlit as st
import base64 as b64                    # [NEW] import base64 module
import struct                           # [NEW] import struct module

# ---------------- RSA FUNCTIONS ---------------- #


st.set_page_config(
    page_title="RSA Encryption App",
    page_icon="🔐",
    layout="centered"
)


def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


RECOMMENDED_PRIMES = [53, 61, 67, 71, 79, 83, 89, 97, 101, 103, 107, 109, 113]


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def modInverse(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    raise ValueError("Modular inverse not found")

def generateKeys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    for e in range(3, phi):
        if gcd(e, phi) == 1:
            break

    d = modInverse(e, phi)

    return e, d, n


def encrypt_text(text, e, n):
    encrypted_numbers = []
    for char in text:
        m = ord(char)
        c = pow(m, e, n)
        encrypted_numbers.append(c)

    # [CHANGED] pack each number as 4-byte integer to support n > 255
    raw_bytes = struct.pack(f"{len(encrypted_numbers)}I", *encrypted_numbers)
    encoded = b64.b64encode(raw_bytes).decode("utf-8")
    return encoded


def decrypt_text(cipher_b64, d, n):
    raw_bytes = b64.b64decode(cipher_b64)

    # [CHANGED] unpack 4-byte integers instead of single bytes
    count = len(raw_bytes) // 4
    encrypted_numbers = struct.unpack(f"{count}I", raw_bytes)

    decrypted = ""
    for c in encrypted_numbers:
        m = pow(c, d, n)
        decrypted += chr(m)
    return decrypted


# ---------------- STREAMLIT UI ---------------- #

st.title("🔐 RSA Encryption / Decryption App")

if "rsa_keys" not in st.session_state:
    st.session_state.rsa_keys = None

if "cipher_b64" not in st.session_state:                      # [NEW] store base64 cipher in session
    st.session_state.cipher_b64 = ""






# ✅ expander goes here — before Step 1
with st.expander("ℹ️ What is RSA?"):
    st.write("""
    RSA is a public-key encryption algorithm. It works by:
    - Generating two keys: a **public key** for encryption and a **private key** for decryption
    - Anyone can encrypt a message using the public key
    - Only the holder of the private key can decrypt it
    """)

st.subheader("1️⃣ Key Generation")

st.write("Recommended primes:")
st.code(RECOMMENDED_PRIMES)

p = st.number_input("Enter prime p", step=1, min_value=0)
q = st.number_input("Enter prime q", step=1, min_value=0)

if st.button("Generate Keys"):
    if not is_prime(int(p)) and not is_prime(int(q)):
        st.error(f"❌ {int(p)} and {int(q)} are both not prime numbers!")
    elif not is_prime(int(p)):
        st.error(f"❌ {int(p)} is not a prime number!")
    elif not is_prime(int(q)):
        st.error(f"❌ {int(q)} is not a prime number!")
    elif p == q:
        st.error("p and q must be different!")
    elif int(p) * int(q) <= 127:
        st.error("p × q must be greater than 127. Use larger primes!")
    else:
        try:
            e, d, n = generateKeys(int(p), int(q))
            st.session_state.rsa_keys = (e, d, n)
            st.success("Keys generated successfully!")
            st.write("Public Key (e, n):", (e, n))
            st.write("Private Key (d, n):", (d, n))
            if n < 256:
                st.warning("⚠️ n is small — some characters may not encrypt correctly. Try larger primes.")
        except ValueError as ex:
            st.error(f"Key generation failed: {ex}")


# ---------------- ENCRYPTION ---------------- #

st.subheader("2️⃣ Encryption")

message = st.text_area("Enter message to encrypt")

if st.button("Encrypt"):
    if st.session_state.rsa_keys is None:
        st.error("Generate keys first!")
    else:
        e, d, n = st.session_state.rsa_keys
        cipher_b64 = encrypt_text(message, e, n)
        st.session_state.cipher_b64 = cipher_b64               # [NEW] save base64 cipher to session

        st.write("🔐 Encrypted message (Base64):")             # [CHANGED] label updated
        st.code(cipher_b64)                                    # [CHANGED] shows base64 string


# ---------------- DECRYPTION ---------------- #

st.subheader("3️⃣ Decryption")

cipher_input = st.text_area(
    "Paste Base64 cipher here",                                # [CHANGED] updated placeholder label
    value=st.session_state.cipher_b64                         # [NEW] auto-fills from encryption
)

if st.button("Decrypt"):
    if st.session_state.rsa_keys is None:
        st.error("Generate keys first!")
    else:
        try:
            e, d, n = st.session_state.rsa_keys
            result = decrypt_text(cipher_input, d, n)          # [CHANGED] pass base64 string directly

            st.success("Decrypted message:")
            st.write(result)

        except Exception as ex:
            st.error(f"Error: {ex}")                           # [CHANGED] shows actual error for easier debugging


if st.button("🔄 Reset", use_container_width=True):
    st.session_state.rsa_keys = None
    st.session_state.cipher_b64 = ""
    st.rerun()
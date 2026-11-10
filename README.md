# RSA Encryption / Decryption App

A small Streamlit app I built to understand how RSA actually works. You type in two primes, it builds a key pair, and then you can encrypt a message and decrypt it again, with every step visible on the page.

It's a learning project, not a security tool. The [limitations](#what-this-is-not) section explains why.

## What it does

- Takes two primes, `p` and `q`, and generates a public key `(e, n)` and a private key `(d, n)`
- Checks your input and tells you exactly what's wrong: one or both numbers aren't prime, `p` and `q` are the same, or `p × q` is too small
- Shows a list of primes that work well, so you don't have to hunt for them (`53, 61, 67, 71, 79, 83, 89, 97, 101, 103, 107, 109, 113`)
- Encrypts a text message and gives you the result as a single Base64 string
- Pre-fills that string in the decryption box, so you can decrypt it with one click (or paste in a ciphertext from earlier)
- Has a Reset button that wipes the keys and ciphertext

## How it works

The RSA part is the textbook version, written by hand in plain Python:

1. `n = p × q` and `phi = (p - 1) × (q - 1)`
2. `e` is the smallest number starting from 3 that shares no factors with `phi`
3. `d` is found by searching for the number where `(e × d) mod phi = 1`
4. Each character is turned into its Unicode code point `m`, then encrypted as `c = m^e mod n`
5. Decryption reverses it: `m = c^d mod n`, then back to a character

To make the output easy to copy around, the list of encrypted numbers is packed into bytes with `struct` (4 bytes per number) and then Base64-encoded. Decryption does the same in reverse.

### A worked example

Using `p = 61` and `q = 53`:

| | |
|---|---|
| `n` | 3233 |
| `phi` | 3120 |
| Public key `(e, n)` | (7, 3233) |
| Private key `(d, n)` | (1783, 3233) |
| Message | `Hi` |
| Ciphertext (Base64) | `PwQAAMwLAAA=` |

Paste that ciphertext into the decryption box with the same keys and you get `Hi` back.

## Running it locally

You need Python 3.8+ and Streamlit.

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
pip install streamlit
streamlit run app.py
```

Streamlit will open the app at `http://localhost:8501`.

## Using the app

1. **Generate keys.** Enter two different primes and click *Generate Keys*. Both keys are displayed.
2. **Encrypt.** Type a message, click *Encrypt*, and copy the Base64 output.
3. **Decrypt.** The ciphertext is already filled in. Click *Decrypt* to see the original message.

A few things to know about your inputs:

- `p × q` must be greater than 127, because every ASCII character has to fit under `n`.
- If `n` is below 256 you'll get a warning, since some characters may not survive the round trip.
- Anything outside basic ASCII (accented letters, emoji) has a code point that can be much larger, so you'll need bigger primes for those.
- Keep the primes reasonably small (a few thousand at most). Each ciphertext number is stored in 4 bytes, so it has to stay under about 4.29 billion.

## What this is not

Please don't use this to protect anything real. The goal was to see the math work, so I kept it simple and left out everything that makes real RSA secure:

- **The keys are tiny.** Real keys are 2048+ bits. Numbers this small can be factored instantly.
- **No padding.** Every character is encrypted on its own and the same letter always gives the same ciphertext, so frequency analysis breaks it easily.
- **The modular inverse is a brute-force loop.** It's fine for small primes but slow for big ones. The Extended Euclidean Algorithm would be the right way.
- **`e` is always the smallest valid value** instead of a standard choice like 65537.

If you need real encryption, use a maintained library such as [`cryptography`](https://cryptography.io/).

## Ideas for next steps

- Replace the brute-force inverse with the Extended Euclidean Algorithm
- Encrypt in blocks instead of one character at a time
- Let users download and upload keys and ciphertext
- Add tests for the key generation and encrypt/decrypt functions

## Project structure

```
app.py      # RSA functions and the Streamlit interface
README.md
```

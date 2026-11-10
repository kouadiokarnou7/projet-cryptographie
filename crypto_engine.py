import secrets

# RFC 3526 / RFC 2409 - 1024-bit MODP Group 2
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
G = 2

def mod_pow(base: int, exp: int, mod: int) -> int:
    """Exponentiation modulaire rapide (Square-and-Multiply)."""
    res = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

def extended_gcd(a: int, b: int):
    """Algorithme d'Euclide étendu : calcule pgcd(a, b) et (x, y) tels que a*x + b*y = pgcd(a, b)."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a: int, m: int) -> int:
    """Inverse modulaire de a modulo m via l'algorithme d'Euclide étendu."""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("L'inverse modulaire n'existe pas.")
    return (x % m + m) % m

def generate_keypair(p: int = P, g: int = G):
    """Génération de paire de clés ElGamal (clé privée x, clé publique y = g^x mod p)."""
    x = secrets.randbelow(p - 3) + 2
    y = mod_pow(g, x, p)
    return x, y

def text_to_blocks(text: str, block_size: int = 64) -> list[int]:
    """Découpe un texte en blocs de bytes puis les convertit en entiers < p."""
    data = text.encode("utf-8")
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        blocks.append(int.from_bytes(chunk, byteorder="big"))
    return blocks

def blocks_to_text(blocks: list[int]) -> str:
    """Reconstitue le texte d'origine à partir des blocs d'entiers."""
    byte_chunks = []
    for num in blocks:
        if num == 0:
            continue
        byte_len = (num.bit_length() + 7) // 8
        byte_chunks.append(num.to_bytes(byte_len, byteorder="big"))
    return b"".join(byte_chunks).decode("utf-8", errors="replace")

def encrypt(blocks: list[int], pubkey: int, p: int = P, g: int = G):
    """Chiffrement ElGamal d'une liste de blocs pour une clé publique donnée."""
    k = secrets.randbelow(p - 3) + 2
    c1 = mod_pow(g, k, p)
    shared_secret = mod_pow(pubkey, k, p)
    c2_list = [(m * shared_secret) % p for m in blocks]
    return c1, c2_list

def decrypt(c1: int, c2_list: list[int], privkey: int, p: int = P) -> list[int]:
    """Déchiffrement ElGamal d'une liste de blocs à l'aide de la clé privée."""
    shared_secret = mod_pow(c1, privkey, p)
    shared_inverse = mod_inverse(shared_secret, p)
    return [(c2 * shared_inverse) % p for c2 in c2_list]


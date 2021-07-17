import collections
import hashlib
import random
def hello():
    print('hello,world')
global k_leak

# Modular arithmetic ##########################################################
def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################
def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):#点加
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)
    return result


def scalar_mult(k, point):#多倍点(标量乘)
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None
    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point
    
    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)
        k >>= 1
        
    assert is_on_curve(result)
    return result

# Keypair generation and ECDSA ################################################
def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)      #私钥d
    public_key = scalar_mult(private_key, curve.g)  #公钥P=dG
    return private_key, public_key


def hash_message(message):
    message_hash = hashlib.sha256(message).digest()
    e = int.from_bytes(message_hash, 'big')
    return e

    #Returns the truncated SHA512 hash of the message.
    #FIPS 180 says that when a hash needs to be truncated, the rightmost bits should be discarded.
    #当需要截断hash时，应丢弃最右边的位。
    '''message_hash = hashlib.sha512(message).digest()
    z = e >> (e.bit_length() - curve.n.bit_length())
    assert z.bit_length() <= curve.n.bit_length()
    return z'''
    
def sign_message(private_key, message):
    e = hash_message(message)
    r = 0
    s = 0
    while not r or not s:
        global k_leak;k_leak = 64373566430140278131327580440284289972164712976330163913406988842791059250706
        print('k的值:',k_leak)
        R_x, R_y = scalar_mult(k_leak, curve.g);r = R_x % curve.n;s = ((e + r * private_key) * inverse_mod(k_leak, curve.n)) % curve.n
        #k = random.randrange(1, curve.n)   #为保障安全性,k随机生成且不能重复使用.如果泄露k会导致泄露密钥d
        '''R_x, R_y = scalar_mult(k, curve.g)
        r = R_x % curve.n
        s = ((e + r * private_key) * inverse_mod(k, curve.n)) % curve.n'''
    return (r, s)


def verify_signature(public_key, message, signature):
    e = hash_message(message)
    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (e * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'

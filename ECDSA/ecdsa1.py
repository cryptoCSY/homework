import collections
import hashlib
import random
import MyECDSA

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')
curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)

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
        #print('k的值:',k_leak)
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

if __name__ == "__main__":
    
    print('Curve:', curve.name)

    d, P = make_keypair()
    print("Private key:", hex(d))
    print("Public key: (0x{:x}, 0x{:x})".format(*P))

    msg = b'How u doing?'
    signature = sign_message(d, msg)

    print()
    print('Message:', msg)
    print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
    print('Verification:', verify_signature(P, msg, signature))

    # (1) Leaking k leads to leaking of d ##########################
    print('\n(1) Leaking k leads to leaking of d:')
    print('泄露的k = {}'.format(hex(k_leak)))
    
    e = hash_message(msg)
    r,s = signature
    d_guess = (inverse_mod(r, curve.n)*(k_leak*s - e))%curve.n
    print('猜测密钥d = {0}'.format(hex(d_guess)))

    if d_guess == d:print('Success!')
    else:print('Failed.')

    # (2) Reusing k leads to leaking of d ##########################
    print('\n(2) Reusing k leads to leaking of d:')
    print('重复使用的k = {}'.format(hex(k_leak)))
    
    m1 = b'ShanDong'
    m2 = b'QingDao'
    signature1 = sign_message(d, m1)
    signature2 = sign_message(d, m2)

    e1 = hash_message(m1);r1 = signature1[0];s1 = signature1[1]
    e2 = hash_message(m2);r2 = signature2[0];s2 = signature2[1]
    
    #根据两条消息及对应的签名恢复私钥
    d_guess2 = ((s2*e1-s1*e2)*inverse_mod(s1*r1-s2*r1, curve.n)) %curve.n
    print('猜测密钥d = {0}'.format(hex(d_guess2)))
    
    if d_guess2 == d:print('Success!')
    else:print('Failed.')

    # (3) Leaking Secret Key Via Reusing k By Different User
    #Two users, using k leads to leaking of d, that is they can deduce each other’s d##########################
    print('\n(3) Leaking Secret Key Via Reusing k By Different User:')
    
    d1, P1 = make_keypair()
    d2, P2 = make_keypair()
    signature_Alice = sign_message(d1, m1)
    e_1 = hash_message(m1)
    r_1 = signature_Alice[0]
    s_1 = signature_Alice[1]
    
    signature_Bob = sign_message(d2, m2)
    e_2 = hash_message(m2)
    r_2 = signature_Bob[0]
    s_2 = signature_Bob[1]
    
    print("Alice的私钥d1:", hex(d1))
    print("Alice的公钥P1: (0x{:x}, 0x{:x})".format(*P1))
    print("Alice签名的消息:",m1)
    print("\nBob的私钥d2:", hex(d2))
    print("Bob的公钥P2: (0x{:x}, 0x{:x})".format(*P2))
    print("Bob签名的消息m2:",m2)
    print()

    #r1=r2
    #Alice恢复Bob的密钥
    d_guess_Bob = ((s_2*e_1-s_1*e_2+s_2*r_1*d1)*inverse_mod(s_1*r_1,curve.n)) % curve.n
    print('Alice恢复Bob的私钥:',hex(d_guess_Bob))
    if d_guess_Bob == d2:print('Success!')
    else:print('Failed.')
    
    #Bob恢复Alice的密钥
    d_guess_Alice = ((s_1*e_2-s_2*e_1+s_1*r_1*d2)*inverse_mod(s_2*r_1,curve.n)) % curve.n
    print('Bob恢复Alice的私钥:',hex(d_guess_Alice))
    if d_guess_Alice == d1:print('Success!')
    else:print('Failed.')

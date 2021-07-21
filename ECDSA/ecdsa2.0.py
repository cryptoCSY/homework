from MyECDSA import curve,inverse_mod,is_on_curve,point_neg,point_add,scalar_mult,make_keypair,hash_message,sign_message,verify_signature
import random
import collections


if __name__ == "__main__":
# (4) (r,s),and (r,-s), are both valid signatures
    #T is they can deduce each other’s d##########################
    print('(4) (r,s),and (r,-s), are both valid signatures:')

    d, P = make_keypair()
    msg = b'ShanDong University'
    print("消息:", msg)
    print("密钥d:", hex(d))
    print("公钥P: (0x{:x}, 0x{:x})".format(*P))
    
    signature = sign_message(d, msg);e1 = hash_message(msg)
    print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
    print('(r,s) Verification:', verify_signature(P, msg, signature))

    r,s = signature
    s_neg = -s%curve.n
    #(r,s)通过验证，(r,-s)同样可以
    signature_forge = (r,s_neg)
    print('(r,-s) Verification:', verify_signature(P, msg, signature_forge))
    
# (5) one can forge signature if the verification does not check m
    print('\n(5) one can forge signature if the verification does not check m:')
    u = random.randrange(1, curve.n)
    v = random.randrange(1, curve.n)
    (x,y) = point_add(scalar_mult(u,curve.g),scalar_mult(v,P))
    r_ = x%curve.n
    e_ = r_*u*inverse_mod(v,curve.n)
    s_ = r_*inverse_mod(v,curve.n)
    
    #Check 可以伪造出哈希值为e_的消息签名
    w = inverse_mod(s_, curve.n)
    u1 = (e_ * w) % curve.n
    u2 = (r_ * w) % curve.n
    (r_forge,s_forge)=point_add(scalar_mult(u1,curve.g),
                                scalar_mult(u2,P))
    if r_forge % curve.n == r_:
        print('Success!')

# (6) Same d and k used in ECDSA & Schnoor signature,leads to leaking of d
    print('\n(6) Same d and k used in ECDSA & Schnoor signature,leads to leaking of d:')
    d1, P1 = make_keypair()
    k = random.randrange(1, curve.n)

    #ECDSA
    m = b'ECDSA'
    e1 = hash_message(m)
    R_x, R_y = scalar_mult(k, curve.g)#R=kG
    r1 = R_x % curve.n
    s1 = ((e1 + r1 * d1) * inverse_mod(k, curve.n)) % curve.n

    #Schnoor signature with same private key d
    R = scalar_mult(k, curve.g)
    R_x = hex(R_x)[2:]
    R_y = hex(R_y)[2:]
    R = R_x+R_y
    #print(R_x,R_y,R)
    
    e2 = hash_message(R.encode('utf-8')+m)
    s2 = (k+e2*d)%curve.n

    s1 = ((e1 + r1 * d1) * inverse_mod(s2-e2*d1, curve.n)) % curve.n
    d_guess = (s1*s2-e1)*inverse_mod(s1*e2+r1,curve.n)%curve.n
    if d_guess == d1:
        print('Success!')

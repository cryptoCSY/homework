import binascii
import math
import random
from MyECDSA import curve,inverse_mod,is_on_curve,point_neg,point_add,scalar_mult,make_keypair,hash_message,sign_message,verify_signature

def Ponit2Standard(P):  #将点转化成标准形式
    P_standard = '04'+hex(P[0])[2:]+hex(P[1])[2:]

def EC_Compress(P): #点压缩
    x = P[1]
    if x%2 == 0:
        compressed_point = '02'+hex(P[0])[2:]
        return compressed_point
    elif x%2 == 1:
        compressed_point = '03'+hex(P[0])[2:]
        return compressed_point

#Cipolla Algo    
def EC_Uncompress(compressed_point): #点解压缩
    p_hex = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
    p = int(p_hex, 16)
    x_hex = compressed_point[2:66]
    x = int(x_hex, 16)
    prefix = compressed_point[0:2]
    
    y_square = (pow(x, 3, p)  + 7) % p
    y_square_square_root = pow(y_square, (p+1)//4, p)
    if (prefix == "02" and y_square_square_root & 1) or (prefix == "03" and not y_square_square_root & 1):
        y = (-y_square_square_root) % p
    else:
        y = y_square_square_root

    computed_y_hex = format(y, '064x')
    computed_uncompressed_key = "04" + x_hex + computed_y_hex

    return computed_uncompressed_key


def quick_algorithm(a,b,c):  #y=a^b%c,a的b次幂余除c
    a = a % c  
    ans = 1  
   #这里我们不需要考虑b<0，因为分数没有取模运算
    while b != 0:  #费马小定理
       if b & 1:  
           ans = (ans * a) % c  
       b>>=1  
       a = (a * a) % c  
    return ans

def IsHaveMoSqrt(x,P):#是否有模平方根y*y=x mod p，已知x，p，判断是否存在y
    ret = quick_algorithm(x,(P-1)//2,P)
    if ret==1:
       return True
    else:
       return False

def GetMoSqrt(x, p):
    """
        求模平方根y*y=x mod p，已知x，p求y

        Args:
            x: 大于0并且小于p的整数。
            p: 质数。

        Returns:
            返回结果y。

        Raises:
            IOError: 无错误。
    """
    if IsHaveMoSqrt(x, p):
        t = 0
        # p-1=(2^t)*s //s是奇数
        s = p - 1
        while s % 2 == 0:
            s = s // 2
            t = t + 1
        if t == 1:
            ret = quick_algorithm(x, (s + 1) // 2, p)
            return ret, p - ret
        elif t >= 2:
            x_ = quick_algorithm(x, p - 2, p)
            n = 1
            while is_have_sqrt_model(n, p):
                n = n + 1
            b = quick_algorithm(n, s, p)
            ret = quick_algorithm(x, (s + 1) // 2, p)
            t_ = 0
            while t - 1 > 0:
                if quick_algorithm(x_ * ret * ret, 2 ** (t - 2), p) == 1:
                    pass
                else:
                    ret = ret * (b ** (2 ** t_)) % p
                t = t - 1
                t_ = t_ + 1
            return ret, p - ret
        else:
            return -2, -2
    else:
        return -1, -1
def Secp256k1GetYByX(x):#y^2=x^3+7 (mod p)根据x求y
    a=(x*x*x+7)%0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    ret = GetMoSqrt(a,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    return ret

if __name__ == "__main__":
    #PoC impl of ec point compression############################################################
    print("(1) EC point compression:")
    d = random.randrange(1, curve.n)    #private key
    P = scalar_mult(d, curve.g) #public key

    P_compressed  = EC_Compress(P)
    computed_uncompressed_key = EC_Uncompress(P_compressed)
    
    print('点P:',hex(P[0]),hex(P[1]))
    print('Compress:',P_compressed)
    print('Uncompress:',computed_uncompressed_key)

    #PoC impl of extracting public key from signature \& verify the signature####################
    print("\n(2) extracting public key from signature & verify the signature:")
    #d, P = make_keypair()
    print("Private key:", hex(d))
    print("Public key: (0x{:x}, 0x{:x})".format(*P))
    
    msg = b'How u doing?'
    e = hash_message(msg)
    
    #signature = sign_message(d, msg)
    k = random.randrange(1, curve.n)
    R_x, R_y = scalar_mult(k, curve.g)
    r = R_x % curve.n
    s = ((e + r * d) * inverse_mod(k, curve.n)) % curve.n

    #R = (R_x, R_y)
    y = Secp256k1GetYByX(r)
    #print(y)
    #print(R_y)
    print('Message:', msg)
    print('Signature: (0x{:x}, 0x{:x})'.format(r,s))

    #Extracting public key from signature
    #关键在于求 R
    
    R1 = (r,y[0])
    P_guess1 = scalar_mult(inverse_mod(r,curve.n),
                        point_add(scalar_mult(s, R1),
                        point_neg(scalar_mult(e,curve.g))
                                )
                           );
    R2 = (r,y[1])
    P_guess2 = scalar_mult(inverse_mod(r,curve.n),
                        point_add(scalar_mult(s, R2),
                        point_neg(scalar_mult(e,curve.g))
                                )
                           );
    print('\n-------------Extracting public key from signature---------------')
    if P_guess1==P:
        P_guess = P_guess1
        print("Public key: (0x{:x}, 0x{:x})".format(*P_guess1))
    elif P_guess2==P:
        P_guess = P_guess2
        print("Public key: (0x{:x}, 0x{:x})".format(*P_guess2))
    print('Verification:', verify_signature(P_guess, msg, (r,s)))
    
    #Schnorr Signature - Batch Verification######################################################
    print("\n(3) Schnorr Signature - Batch Verification:")
    m1 = b'SHANDONG'
    m2 = b'QINGDAO'
    #攻击者私钥 x1 和公钥 P1
    x1 = random.randrange(1, curve.n)
    P1 = scalar_mult(x1, curve.g)
    
    #攻击者伪造公钥为 P2 的签名(攻击者不知道私钥 x2 )
    P2 = scalar_mult(random.randrange(1, curve.n), curve.g)

    #攻击者随机选择 r2 , s2 ; 并计算 e2
    r2 = random.randint(1, curve.n);s2 = random.randint(1, curve.n)
    R2 = scalar_mult(r2, curve.g)
    #e2=h(P2||R2||m2)
    e2 = hash_message((hex(P2[0])[2:]+hex(P2[1])[2:]).encode('utf-8') +
                              (hex(R2[0])[2:]+hex(R2[1])[2:]).encode('utf-8') +
                              m2)

    #攻击者设置特定的R1; 并计算e1,s1
    R1 = scalar_mult(-e2, P2)
    e1 = hash_message((hex(P1[0])[2:]+hex(P1[1])[2:]).encode('utf-8') +
                              (hex(R1[0])[2:]+hex(R1[1])[2:]).encode('utf-8') +
                              m1)
    s1 = (r2+e1*x1-s2) % curve.n


    #(R1,s1)和(R2,s2)可以通过验证
    e1xP1=scalar_mult(e1,P1)
    e2xP2=scalar_mult(e2,P2)
    if scalar_mult(s1+s2, curve.g) == point_add(R1,point_add(R2,point_add(e1xP1,e2xP2))):
        print('Success!')

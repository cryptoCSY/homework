import binascii
import math
import random
import MyECDSA

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

def EC_Compress(P):#点压缩P
    y = Secp256k1GetYByX(P[0])
    if y[0]==P[0]:
        compressed_point = '02'+hex(P[0])[2:]
        return compressed_point
    elif y[0]==P[1]:
        compressed_point = '03'+hex(P[0])[2:]
        return compressed_point

def EC_Extract(compressed_point):
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
    
if __name__ == "__main__":
    d = random.randrange(1, MyECDSA.curve.n)
    P = MyECDSA.scalar_mult(d, MyECDSA.curve.g)
    print('点P:',hex(P[0]),hex(P[1]))
#EC point compression
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
    #g_compressed = EC_Compress(g)
    P_compressed  = EC_Compress(P)
#Compress public key into signature,extract public key from signature & verify the signature
    computed_uncompressed_key = EC_Extract(P_compressed)
    print('P解压缩:',computed_uncompressed_key)
    '''p_hex = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
    p = int(p_hex, 16)
    compressed_key_hex = '0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352'
    x_hex = compressed_key_hex[2:66]
    x = int(x_hex, 16)
    prefix = compressed_key_hex[0:2]

    y_square = (pow(x, 3, p)  + 7) % p
    y_square_square_root = pow(y_square, (p+1)//4, p)
    if (prefix == "02" and y_square_square_root & 1) or (prefix == "03" and not y_square_square_root & 1):
        y = (-y_square_square_root) % p
    else:
        y = y_square_square_root

    computed_y_hex = format(y, '064x')
    computed_uncompressed_key = "04" + x_hex + computed_y_hex

    print(computed_uncompressed_key)'''

#Schnorr Signature – Batch Verification
    print("\n(3) Schnorr Signature - Batch Verification:")
    m1 = b'SHANDONG'
    m2 = b'QINGDAO'
    #攻击者私钥x1和公钥P1
    x1 = random.randrange(1, MyECDSA.curve.n)
    P1 = MyECDSA.scalar_mult(x1, MyECDSA.curve.g)

    '''k1 = random.randrange(1, MyECDSA.curve.n)
    R = MyECDSA.scalar_mult(k1, MyECDSA.curve.g)
    R_x = hex(R[0])[2:]
    R_y = hex(R[1])[2:]
    R = R_x+R_y'''
    
    #攻击者伪造公钥为P2的签名(攻击者不知道私钥x2)
    P2 = MyECDSA.scalar_mult(random.randrange(1, MyECDSA.curve.n), MyECDSA.curve.g)

    #攻击者随机选择r2,s2; 并计算e2
    r2 = random.randint(1, MyECDSA.curve.n);s2 = random.randint(1, MyECDSA.curve.n)
    R2 = MyECDSA.scalar_mult(r2, MyECDSA.curve.g)
    #e2=h(P2||R2||m2)
    e2 = MyECDSA.hash_message((hex(P2[0])[2:]+hex(P2[1])[2:]).encode('utf-8') +
                              (hex(R2[0])[2:]+hex(R2[1])[2:]).encode('utf-8') +
                              m2)

    #攻击者设置特定的R1; 并计算e1,s1
    R1 = MyECDSA.scalar_mult(-e2, P2)
    e1 = MyECDSA.hash_message((hex(P1[0])[2:]+hex(P1[1])[2:]).encode('utf-8') +
                              (hex(R1[0])[2:]+hex(R1[1])[2:]).encode('utf-8') +
                              m1)
    s1 = (r2+e1*x1-s2) % MyECDSA.curve.n


    #(R1,s1)和(R2,s2)可以通过验证
    e1xP1=MyECDSA.scalar_mult(e1,P1)
    e2xP2=MyECDSA.scalar_mult(e2,P2)
    if MyECDSA.scalar_mult(s1+s2, MyECDSA.curve.g) == MyECDSA.point_add(R1,
                                                                        MyECDSA.point_add
                                                                        (R2,MyECDSA.point_add
                                                                         (e1xP1,e2xP2))):
        print('Success!')
    





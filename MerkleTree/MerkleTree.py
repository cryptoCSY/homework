import copy
import hashlib

def hash_leaf(data,hash_function = 'sha256'):#merkle树叶节点
    hash_function = getattr(hashlib, hash_function)
    data = b'\x00'+data.encode('utf-8')
    #print(data)
    return hash_function(data).hexdigest()
    
def hash_node(data,hash_function = 'sha256'):#merkle树其它节点
    hash_function = getattr(hashlib, hash_function)
    data = b'\x01'+data.encode('utf-8')
    #print(data)
    return hash_function(data).hexdigest()

lst = ['a','b','c','d','e','f','g']
#100k 大小测试集
'''lst = []
for i in range(100000):
    lst.append(str(i))'''

def Create_Merkle_Tree(lst,hash_function = 'sha256'):
    lst_hash = []
    for i in lst:
        lst_hash.append(hash_leaf(i))
    #print("lst_hash done")
    #print('lst_hash:',lst_hash)
    merkle_tree = [copy.deepcopy(lst_hash)]#用多维列表表示mekle树

    if len(lst_hash)<2:print("no tracnsactions to be hashed");return 0
    h = 0 #merkle树高度
    while len(lst_hash) >1:
        h += 1
        if len(lst_hash)%2 == 0:#偶数节点
            v = []
            while len(lst_hash) >1 :
                a = lst_hash.pop(0)
                b = lst_hash.pop(0)
                v.append(hash_node(a+b, hash_function))
            #print('\nv:',v);print('len(v):',len(v))
            merkle_tree.append(v[:])#merkle树更新一层;[:]切片深复制效果
            #print('merkle_tree:',merkle_tree)
            lst_hash = v
        else:#奇数节点
            v = []
            last_node = lst_hash.pop(-1)
            while len(lst_hash) >1 :
                a = lst_hash.pop(0)
                b = lst_hash.pop(0)
                v.append(hash_node(a+b, hash_function))
            v.append(last_node)
            #print('v:',v);print('len(v):',len(v))
            merkle_tree.append(v[:])#merkle树更新一层
            #print('merkle_tree:',merkle_tree)
            lst_hash = v
    return merkle_tree,h

#构造第n个叶子节点存在性和验证
def Audit_Proof(merkle_tree,h,n,leaf,hash_function = 'sha256'):#h为Merkle树高度，n为查找的序号
    if n>len(merkle_tree[0]):print("节点序号有误！");return 0
    print("序号:{0}，字符:{1}\n查找路径:".format(n,leaf))
    j=0 #第j层,最底层需要计算叶子节点哈希值
    L = len(merkle_tree[0])
    if L%2 == 1 and L-1==n:#叶节点为奇数个，且n为最后一个节点
        hash_value = hash_leaf(leaf)
        print('第{0}层Hash值:{1}'.format(j+1,hash_value))
    elif n%2==1:
        hash_value = hash_node(merkle_tree[0][n-1]+hash_leaf(leaf),hash_function)
        print('第{0}层查询值:{1}，生成的Hash值:{2}'.format(j+1,merkle_tree[0][n-1],hash_value))
    elif n%2==0:
        hash_value = hash_node(hash_leaf(leaf)+merkle_tree[0][n+1],hash_function)
        print('第{0}层查询值:{1}，生成的Hash值:{2}'.format(j+1,merkle_tree[0][n+1],hash_value))
    n = n//2
    j += 1 
    while j<h:#查询兄弟节点哈希值，生成新哈希值
        L = len(merkle_tree[j])
        if L%2 == 1 and L-1==n:#节点为奇数个，且n为最后一个节点
            print('第{0}层Hash值:{1}'.format(j+1,hash_value))
        elif n%2==1:
            hash_value = hash_node(merkle_tree[j][n-1]+hash_value,hash_function)
            print('第{0}层查询值:{1}，生成的Hash值:{2}'.format(j+1,merkle_tree[j][n-1],hash_value))
        elif n%2==0:
            hash_value = hash_node(hash_value+merkle_tree[j][n+1],hash_function)
            print('第{0}层查询值:{1}，生成的Hash值:{2}'.format(j+1,merkle_tree[j][n+1],hash_value))
        n = n//2
        j += 1

    #print(hash_value)
    print('\n根节点哈希值:',merkle_tree[h][0])
    if hash_value==merkle_tree[h][0]:print("节点%s在Merkle树中"%leaf)
    else:print("节点%s不在Merkle树中"%leaf)

merkle_tree,h = Create_Merkle_Tree(lst)
#leaf = input('要查找的节点：')
#p = int(input('节点序号：'))
#Audit_Proof(merkle_tree,h,p,leaf)
Audit_Proof(merkle_tree,h,5,'f')

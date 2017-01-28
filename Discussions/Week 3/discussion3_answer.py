from crypto.tools import split, xor_strings
from crypto.ideal.block_cipher import BlockCipher

# Block & key size in bytes.
block_len = 16 #  == k above
key_len = 16   #  == k above

#PRF F
F = BlockCipher(block_len, key_len).encrypt

"""
G1 and G2 are the first two attempted PRF constructions on the last PRF slide.
Try to write attacks against them in A_1 and A_2.
"""

def G1(k, x):
    xbar = xor_strings(x, "\xFF" * block_len)
    
    y1 = F(k,x)
    y2 = F(k,xbar)

    return y1 + y2    

def A_1(fn):
    output1 = fn("\x00" * block_len)
    output2 = fn("\xFF" * block_len)
    y1, y2 = split(output1)
    y3, y4 = split(output2)

    if(y2+y1 == y3+y4):
        return 1 #I think I'm in Real
    else:
        return 0 #I think I'm in Rand

    pass

def G2(k, x):
    y1 = F(k,x)
    y2 = F(k,y1)

    return y1 + y2 

def A_2(fn):
    output1 = fn("\x00" * block_len)
    y1, y2 = split(output1)

    output2 = fn(y1)
    y3, y4 = split(output2)
    
    if(y2 == y3):
        return 1 #I think I'm in Real
    else:
        return 0 #I think I'm in Rand

    pass


from crypto.games.game_prf import GamePRF
from crypto.simulator.world_sim import WorldSim

if __name__ == '__main__':
    g_1 = GamePRF(G1, key_len, block_len, 2* block_len)
    s_1 = WorldSim(g_1, A_1)

    g_2 = GamePRF(G2, key_len, block_len, 2* block_len)
    s_2 = WorldSim(g_2, A_2)

    print "The advantage of your adversary A_1 is ~" + \
                                        str(s_1.compute_advantage())

    print "The advantage of your adversary A_2 is ~" + \
                                        str(s_2.compute_advantage())


from typing import List
#import textwrap

# create a data structure to hold all of the substitution boxes for DES algorithm => provides non-linearity in the cipher
sbox =[
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]

def remove_parity_bits(key: str) -> str:
    return ''.join(key[i:i+7] for i in range(0, len(key), 8))


# create function to prepare the key by generating subkeys for each round of DES algorithm
def generateSubkeys(key: str) -> List[str]:
        
    leftShifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    # define tables for permuteBlock choice 1 and 2
    pc1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]
    pc2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

    # permute key according to PC1 and split into left and right halves
    
    permutedKey = "".join(key[i - 1] for i in pc1)
    leftSide = permutedKey[:28]
    rightSide = permutedKey[28:]

    subkeys = []
    for shift in leftShifts:
        # left shift both halves and combine them
        leftSide = leftSide[shift:] + leftSide[:shift]
        rightSide = rightSide[shift:] + rightSide[:shift]
        joined = leftSide + rightSide


        # permute joined sides and use pc2 to create the subkeys
        subkey = "".join(joined[i - 1] for i in pc2)
        subkeys.append(subkey)

    return subkeys


def expansion(block: str) -> str:
    exp = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    return "".join(block[i - 1] for i in exp)

def firstPermute(data: str) -> str:
    firstP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    return "".join(data[i - 1] for i in firstP)



# create function to apply the S-Box substitutions
def applysboxSubs(expanded_block: str) -> str:
    out = ""
    for i in range(8):
        block = expanded_block[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        out += format(sbox[i][row*16 + col], '04b')

    return out

# create function to do the XOR operation on the vits
def XOR(a: str, b: str) -> str:
    return ''.join('1' if i != j else '0' for i, j in zip(a, b))

def permuteBlock(block: str) -> str:
    # table to hold the permutations
    perms = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]
    return "".join(block[i - 1] for i in perms)


def lastPermute(data: str) -> str:
    lastP = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    return "".join(data[i - 1] for i in lastP)

def desDecryption(ciphertext: str, subkeys: List[str]) -> str:
    
    dataPermute = firstPermute(ciphertext)

    left = dataPermute[:32]
    right = dataPermute[32:]

    # perform the 16 rounds of DES processing
    for i in range(16):
        subkey = subkeys[15 - i]
        # perform the expansion in the ruight half
        rightExp = expansion(right)
        m = XOR(rightExp, subkey)
        sub = applysboxSubs(m)
        permuted = permuteBlock(sub)
        print(f"Current Round {i+1} with f output: {permuted}")
        
        updatedRight = XOR(left, permuted)

        # perform the swap after XOR 
        left = right
        right = updatedRight

        print(f"Current Round: {i+1} with LnRn: {left}{right}")
    
    return left + right


def binaryToText(binaryString: str) -> str:
    sol = ''
    for i in range(0, len(binaryString), 8):
        b = binaryString[i:i+8]
        print(b, int(b, 2))
        sol += chr(int(b, 2))
    return sol

# def binaryToText(binaryStr: str) -> str:
#     # use textwrap to split the string into chunks of 8 bits
#     byte_chunks = textwrap.wrap(binaryStr, 8)
#     # convert each chunk to a decimal, then to a character, and join the result
#     return ''.join(chr(int(byte, 2)) for byte in byte_chunks)

ciphertext = "1100101011101101101000100110010101011111101101110011100001110011"
key = "0100110001001111010101100100010101000011010100110100111001000100"
subkeys = generateSubkeys(key)

# Decrypt the message and print plaintext conversion 
decrypted_data = desDecryption(ciphertext, subkeys)
decrypted_data = lastPermute(decrypted_data)
plaintext = binaryToText(decrypted_data)
print(f"Plaintext: {plaintext}")
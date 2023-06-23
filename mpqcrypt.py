from ctypes import *

class MpqCrypt():

    # Decryption keys for MPQ tables
    MPQ_KEY_HASH_TABLE   =   0xC3AF3770  # Obtained by HashString("(hash table)", MPQ_HASH_FILE_KEY)
    MPQ_KEY_BLOCK_TABLE  =   0xEC83B3A3  # Obtained by HashString("(block table)", MPQ_HASH_FILE_KEY)
    MPQ_HASH_TABLE_INDEX =   0x000
    MPQ_HASH_NAME_A      =   0x100
    MPQ_HASH_NAME_B      =   0x200
    MPQ_HASH_FILE_KEY    =   0x300
    MPQ_HASH_KEY2_MIX    =   0x400

    STORM_BUFFER_SIZE    =   0x500

    StormBuffer = (c_uint32 * STORM_BUFFER_SIZE)()   # Buffer for the decryption engine

    def __init__(self):
        dwSeed = 0x00100001

        # Initialize the decryption buffer.
        for index1 in range(0x100):
            for index2 in range(index1, index1 + 0x500, 0x100):
                dwSeed = (dwSeed * 125 + 3) % 0x2AAAAB
                temp1  = (dwSeed & 0xFFFF) << 0x10

                dwSeed = (dwSeed * 125 + 3) % 0x2AAAAB
                temp2  = (dwSeed & 0xFFFF)

                try:
                    self.StormBuffer[index2] = temp1 | temp2
                except:
                    print(index2, len(self.StormBuffer))
                    raise()

    #
    # Note: Implementation of this function in WorldEdit.exe and storm.dll
    # incorrectly treats the character as signed, which leads to the
    # a buffer underflow if the character in the file name >= 0x80:
    # The following steps happen when *pbKey == 0xBF and dwHashType == 0x0000
    # (calculating hash index)
    #
    # 1) Result of AsciiToUpperTable_Slash[*pbKey++] is sign-extended to 0xffffffbf
    # 2) The "ch" is added to dwHashType (0xffffffbf + 0x0000 => 0xffffffbf)
    # 3) The result is used as index to the StormBuffer table,
    # thus dereferences a random value BEFORE the begin of StormBuffer.
    #
    # As result, MPQs containing files with non-ANSI characters will not work between
    # various game versions and localizations. Even WorldEdit, after importing a file
    # with Korean characters in the name, cannot open the file back.
    #
    def HashString(self, szFileName, dwHashType):
        dwSeed1 = 0x7FED7FED
        dwSeed2 = 0xEEEEEEEE

        # Convert the input character to uppercase
        # Convert slash (0x2F) to backslash (0x5C)
        szFileName = szFileName.upper()
        szFileName = szFileName.replace('/', '\\')

        for i in range(len(szFileName)):
            ch = ord(szFileName[i])

            dwSeed1 = self.StormBuffer[(dwHashType + ch) & 0xFFFFFFFF] ^ ((dwSeed1 + dwSeed2) & 0xFFFFFFFF)
            dwSeed2 = (ch + dwSeed1 + dwSeed2 + (dwSeed2 << 5) + 3) & 0xFFFFFFFF

        return dwSeed1

    def DecryptMpqBlock(self, ui32_arr, dwKey1):
        dwKey2 = 0xEEEEEEEE

        for i in range(len(ui32_arr)):
            # Modify the second key
            dwKey2 += self.StormBuffer[self.MPQ_HASH_KEY2_MIX + (dwKey1 & 0xFF)]
            dwKey2 &= 0xFFFFFFFF

            dwValue32 = ui32_arr[i] ^ ((dwKey1 + dwKey2) & 0xFFFFFFFF)
            ui32_arr[i] = dwValue32

            dwKey1 = (((~dwKey1 << 0x15) + 0x11111111) & 0xFFFFFFFF) | (dwKey1 >> 0x0B)
            dwKey2 = dwValue32 + dwKey2 + (dwKey2 << 5) + 3
            dwKey2 &= 0xFFFFFFFF

    def EncryptMpqBlock(self, ui32_arr, dwKey1):
        dwKey2 = 0xEEEEEEEE

        for i in range(len(ui32_arr)):
            # Modify the second key
            dwKey2 += self.StormBuffer[self.MPQ_HASH_KEY2_MIX + (dwKey1 & 0xFF)];

            dwValue32 = ui32_arr[i]
            ui32_arr[i] = dwValue32 ^ ((dwKey1 + dwKey2) & 0xFFFFFFFF)

            dwKey1 = (((~dwKey1 << 0x15) + 0x11111111) & 0xFFFFFFFF) | (dwKey1 >> 0x0B)
            dwKey2 = dwValue32 + dwKey2 + (dwKey2 << 5) + 3
            dwKey2 &= 0xFFFFFFFF
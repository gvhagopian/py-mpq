from ctypes import *
import collections
from functools import partial
import sys
import os
import re

from mpqcrypt import MpqCrypt
import mpqcompress as cmpr

MPQ_FILE_IMPLODE          =  0x00000100  # Implode method (By PKWARE Data Compression Library)
MPQ_FILE_COMPRESS         =  0x00000200  # Compress methods (By multiple methods)
MPQ_FILE_ENCRYPTED        =  0x00010000  # Indicates whether file is encrypted
MPQ_FILE_FIX_KEY          =  0x00020000  # File decryption key has to be fixed
MPQ_FILE_PATCH_FILE       =  0x00100000  # The file is a patch file. Raw file data begin with TPatchInfo structure
MPQ_FILE_SINGLE_UNIT      =  0x01000000  # File is stored as a single unit, rather than split into sectors (Thx, Quantam)
MPQ_FILE_DELETE_MARKER    =  0x02000000  # File is a deletion marker. Used in MPQ patches, indicating that the file no longer exists.
MPQ_FILE_SECTOR_CRC       =  0x04000000  # File has checksums for each sector.
                                         # Ignored if file is not compressed or imploded.
MPQ_FILE_SIGNATURE        =  0x10000000  # Present on STANDARD.SNP\(signature). The only occurence ever observed
MPQ_FILE_EXISTS           =  0x80000000  # Set if file exists, reset when the file was deleted
MPQ_FILE_REPLACEEXISTING  =  0x80000000  # Replace when the file exist (SFileAddFile)

MPQ_FILE_COMPRESS_MASK    =  0x0000FF00  # Mask for a file being compressed

HEADER_FNAME = "header.bin"

data2ext = [
    (b"^RIFF"                   , "wav" ),
    (b"^<(?:htm|HTM)"           , "html"),
    (b"^Woo!"                   , "tbl" ),    # Table files
    (b"^BLP[012]"               , "blp" ),    # BLP textures
    (b"^\x4D\x44\x4C\x58"       , "mdx" ),    # MDX files
    (b"^GIF8"                   , "gif" ),    # GIF images
    (b"^\xFF\xD8\xFF\xE0"       , "jpg" ),    # JPEG image
    (b"^\x1B\x4C\x75\x61"       , "lua" ),    # Compiled LUA files
    (b"^DDS "                   , "dds" ),    # DDS textures
    (b"^fLaC"                   , "flac"),    # FLAC sound files
    (b"^\xFF[\xF2\xF3\xFB]|ID3" , "mp3" ),    # MP3 sound files
    (b"^W3do"                   , "doo" ),    # Warcraft III doodad files
    (b"^W3\x45\x21"             , "w3e" ),    # Warcraft III environment files
    (b"^\x4D\x50\x33\x57"       , "wpm" ),    # Warcraft III pathing map files
    (b"^\x57\x54\x47\x21"       , "wtg" ),    # Warcraft III trigger files
    (b"^[!-~\s]+$"              , "txt" ),    # content seems printable ascii
]

class HeaderV1(LittleEndianStructure):
    _fields_ = [
        # The ID_MPQ ('MPQ\x1A') signature
        ("dwID", c_uint32),
        # Size of the archive header
        ("dwHeaderSize", c_uint32),

        # Size of MPQ archive
        # This field is deprecated in the Burning Crusade MoPaQ format, and the size of the archive
        # is calculated as the size from the beginning of the archive to the end of the hash table,
        # block table, or extended block table (whichever is largest).
        ("dwArchiveSize", c_uint32),

        # 0 = Format 1 (up to The Burning Crusade)
        # 1 = Format 2 (The Burning Crusade and newer)
        # 2 = Format 3 (WoW - Cataclysm beta or newer)
        # 3 = Format 4 (WoW - Cataclysm beta or newer)
        ("wFormatVersion", c_uint16),

        # Power of two exponent specifying the number of 512-byte disk sectors in each logical sector
        # in the archive. The size of each logical sector in the archive is 512 * 2^wBlockSize.
        ("wBlockSize", c_uint16),

        # Offset to the beginning of the hash table, relative to the beginning of the archive.
        ("dwHashTablePos", c_uint32),

        # Offset to the beginning of the block table, relative to the beginning of the archive.
        ("dwBlockTablePos", c_uint32),

        # Number of entries in the hash table. Must be a power of two, and must be less than 2^16 for
        # the original MoPaQ format, or less than 2^20 for the Burning Crusade format.
        ("dwHashTableSize", c_uint32),

        # Number of entries in the block table
        ("dwBlockTableSize", c_uint32),
    ]

class MpqHash(LittleEndianStructure):
    _fields_ = [
        # The hash of the full file name (part A)
        ("dwName1", c_uint32),

        # The hash of the full file name (part B)
        ("dwName2", c_uint32),

        # The language of the file. This is a Windows LANGID data type, and uses the same values.
        # 0 indicates the default language (American English), or that the file is language-neutral.
        ("lcLocale", c_uint16),

        # The platform the file is used for. 0 indicates the default platform.
        # No other values have been observed.
        ("wPlatform", c_uint16),

        # If the hash table entry is valid, this is the index into the block table of the file.
        # Otherwise, one of the following two values:
        #  - FFFFFFFFh: Hash table entry is empty, and has always been empty.
        #               Terminates searches for a given file.
        #  - FFFFFFFEh: Hash table entry is empty, but was valid at some point (a deleted file).
        #               Does not terminate searches for a given file.
        ("dwBlockIndex", c_uint32),
    ]

# File description block contains informations about the file
class MpqBlock(LittleEndianStructure):
    _fields_ = [
        # Offset of the beginning of the file data, relative to the beginning of the archive.
        ("dwFilePos", c_uint32),

        # Compressed file size
        ("dwCSize", c_uint32),

        # Size of uncompressed file
        ("dwFSize", c_uint32),

        # Flags for the file. See the table below for more informations
        ("dwFlags", c_uint32),
    ]

class MpqArchive():

    def __init__(self):

        self.crypt = MpqCrypt()

        self.archive_start = 0
        self.header = HeaderV1()

    def read_header(self, fin):
        fin.seek(0)
        fin.readinto(self.header)
        self.sector_size = 512 * (1 << self.header.wBlockSize)

    def read_tables(self, fin):
        self.htable = self.read_table(fin,
            self.header.dwHashTablePos,
            self.header.dwHashTableSize,
            MpqHash,
            self.crypt.MPQ_KEY_HASH_TABLE)

        self.btable = self.read_table(fin,
            self.header.dwBlockTablePos,
            self.header.dwBlockTableSize,
            MpqBlock,
            self.crypt.MPQ_KEY_BLOCK_TABLE)

    def read_table(self, fin, pos, count, ttype, key):
        buf32 = (c_uint32 * (count * sizeof(ttype) >> 2))()
        fin.seek(self.archive_start + pos)
        fin.readinto(buf32)

        self.crypt.DecryptMpqBlock(buf32, key)

        table = (ttype * count)()
        memmove(table, buf32, count * sizeof(ttype))

        return table

    def write_table(self, fout, count, ttype, table, key):
        buf32 = (c_uint32 * (count * sizeof(ttype) >> 2))()
        memmove(buf32, table, count * sizeof(ttype))

        self.crypt.EncryptMpqBlock(buf32, key)
        fout.write(bytes(buf32))

    def iter_files(self):
        pass

    def add_file(self):
        pass

def extract_mpq(mpq, mpq_fin, dest_dir):

    consec_htent = 0

    header_fpath = os.path.join(dest_dir, HEADER_FNAME)
    with open(header_fpath, "wb") as fout:
        fout.write(bytes(mpq.header))

    dest_dir_anon = os.path.join(dest_dir, "contents_anonymous")

    for i, htent in enumerate(mpq.htable):
        if htent.dwBlockIndex == 0xFFFFFFFF:
            consec_htent = 0
            continue
        if htent.dwBlockIndex >= len(mpq.btable):
            print("entry outside block table")
            print(htent.dwBlockIndex)
            print(htent.dwName1)
            print(htent.dwName2)
            break
            continue
        blk = mpq.btable[htent.dwBlockIndex]


        n_sectors = 1 + blk.dwFSize // mpq.sector_size

        # offset table is signed; data can precede offset table
        sector_offset_table = (c_int32 * (n_sectors + 1))()
        mpq_fin.seek(blk.dwFilePos)
        mpq_fin.readinto(sector_offset_table)

        decmpr_data = b""
        cmpr_data = []

        for j in range(n_sectors):
            sector_pos = blk.dwFilePos + sector_offset_table[j]
            sector_size = sector_offset_table[j + 1] - sector_offset_table[j]

            mpq_fin.seek(sector_pos)

            if blk.dwFlags & MPQ_FILE_COMPRESS_MASK:
                sector_cmpr_byte = ord(mpq_fin.read(1))
                sector_cmpr_data = mpq_fin.read(sector_size - 1)
                cmpr_data.append((sector_cmpr_byte, sector_cmpr_data))
            else:
                decmpr_data += mpq_fin.read(sector_size)

        if blk.dwFlags & MPQ_FILE_COMPRESS_MASK:
            try:
                for sector_cmpr_byte, sector_cmpr_data in cmpr_data:
                    decmpr_data += cmpr.decmpr_sector(sector_cmpr_byte, sector_cmpr_data)
            except cmpr.MethodUnsupportedError as exc:
                decmpr_data = b""

        file_id = str.format("{hash_index:06d}_{h.dwName1:08X}_{h.dwName2:08X}_{h.lcLocale:04X}_{h.wPlatform:04X}",
            hash_index = i, h = htent)

        if decmpr_data:
            for pattern, ext in data2ext:
                if re.search(pattern, decmpr_data[0:10]):
                    break
            else:
                ext = "bin"

            fname = "%s.%s" % (file_id, ext)
            with open(os.path.join(dest_dir_anon, fname), "wb") as fout:
                fout.write(decmpr_data)
        else:
            for i, (sector_cmpr_byte, sector_cmpr_data) in enumerate(cmpr_data):
                fname = "%s.%04d_%02X_%08X" % (file_id, i, sector_cmpr_byte, blk.dwFSize)
                with open(os.path.join(dest_dir_anon, fname), "wb") as fout:
                    fout.write(sector_cmpr_data)

        consec_htent += 1

def assemble_mpq(mpq, src_dir, fout_dest):

    mpq = MpqArchive()
    header_fpath = os.path.join(src_dir, HEADER_FNAME)
    with open(header_fpath, "rb") as fin:
        mpq.read_header(fin)
        fin.seek(0)
        fout_dest.write(fin.read())

    mpq.htable = (MpqHash * mpq.header.dwHashTableSize)()
    for i in range(mpq.header.dwHashTableSize):
        mpq.htable[i].dwBlockIndex = 0xFFFFFFFFF

    block_data = b""

    src_dir_anon = os.path.join(src_dir, "contents_anonymous")
    src_files_anon = [_ for _ in os.listdir(src_dir_anon)]

    file_to_exts = collections.defaultdict(list)

    for fname, ext in map(os.path.splitext, src_files_anon):
        file_to_exts[fname].append(ext)

    for fname, ext_list in file_to_exts.items():
        fname_pattern = re.match("(\d{6})_"
            "([0-9A-F]{8})_([0-9A-F]{8})_"
            "([0-9A-F]{4})_([0-9A-F]{4})", fname)

        assert(fname_pattern)
        hidx, name1, name2, locale, platform = map(int, fname_pattern.groups(), [10, 16, 16, 16, 16])

        fpath = os.path.join(src_dir_anon, fname)

        assert(hidx < mpq.header.dwHashTableSize)
        mpq.htable[hidx].dwName1 = name1
        mpq.htable[hidx].dwName2 = name2
        mpq.htable[hidx].lcLocale = locale
        mpq.htable[hidx].wPlatform = platform
        mpq.htable[hidx].dwBlockIndex = len(block_data) // sizeof(MpqBlock)

        block = MpqBlock()

        n_sectors = len(ext_list) if len(ext_list) > 1 else 1 + os.stat(fpath + ext_list[0]).st_size // mpq.sector_size
        sector_offset_table = (c_int32 * (n_sectors + 1))()

        sector_table_pos = fout_dest.tell()
        # write a placeholder as the sector offsets aren't known yet
        fout_dest.write(bytes(sector_offset_table))

        sector_offset_table[0] = sizeof(sector_offset_table)
        next_sector_idx = 1

        for ext in sorted(ext_list):
            with open(fpath + ext, "rb") as fin:
                while True:
                    file_data = fin.read(mpq.sector_size)
                    if file_data == b"":
                        break

                    sector_size = len(file_data) + 1
                    ext_matches_precompressed = re.match("\d{4}_([0-9A-Z]{2})_([0-9A-Z]{8})", ext)
                    if ext_matches_precompressed:
                        assert(sector_size < mpq.sector_size) # should already be one compressed chunk
                        encr_byte, block.dwFSize = map(int(ext_matches_precompressed.groups(), [16, 16]))
                        block.dwCSize += len(file_data)
                        fout_dest.write(bytes(chr(encr_byte), "ascii"))
                        fout_dest.write(file_data)
                    else:
                        block.dwFSize += len(file_data)
                        cmpr_data = cmpr.cmpr_sector(cmpr.CMPR_METHOD_ZLIB, file_data)
                        block.dwCSize += len(cmpr_data)
                        sector_size = len(cmpr_data) + 1
                        fout_dest.write(bytes(chr(cmpr.CMPR_METHOD_ZLIB), "ascii"))
                        fout_dest.write(cmpr_data)

                    sector_offset_table[next_sector_idx] = sector_offset_table[next_sector_idx - 1] + sector_size
                    next_sector_idx += 1

        # go back and write the sector offset table
        fout_dest.seek(sector_table_pos)
        fout_dest.write(bytes(sector_offset_table))
        fout_dest.seek(0, os.SEEK_END)

        block.dwFilePos = sector_table_pos
        block.dwFlags = MPQ_FILE_EXISTS | MPQ_FILE_COMPRESS

        block_data += bytes(block)


    # write encrypted hash table
    mpq.header.dwHashTablePos = fout_dest.tell()
    mpq.write_table(fout_dest, mpq.header.dwHashTableSize, MpqHash, mpq.htable, mpq.crypt.MPQ_KEY_HASH_TABLE)

    # write encrypted block table
    mpq.header.dwBlockTablePos = fout_dest.tell()
    mpq.header.dwBlockTableSize = len(block_data) // sizeof(MpqBlock)
    mpq.btable = (MpqBlock * mpq.header.dwBlockTableSize)()
    memmove(mpq.btable, block_data, sizeof(MpqBlock) * mpq.header.dwBlockTableSize)
    mpq.write_table(fout_dest, mpq.header.dwBlockTableSize, MpqBlock, mpq.btable, mpq.crypt.MPQ_KEY_BLOCK_TABLE)

    # rewrite header so file reflects updated table position and size values
    mpq.header.dwArchiveSize = fout_dest.tell() + sizeof(mpq.header)
    fout_dest.seek(0)
    fout_dest.write(bytes(mpq.header))



def main():
    op = sys.argv[1]

    if op == "extract":
        src_fname = sys.argv[2]
        dest_dir = "%s_data" % os.path.splitext(src_fname)[0]
        for dir in map(partial(os.path.join, dest_dir), ["contents", "contents_anonymous"]):
            if not os.path.exists(dir):
                os.makedirs(dir)
            else:
                assert(os.path.isdir(dir))

        with open(src_fname, "rb") as mpq_fin:
            mpq = MpqArchive()
            mpq.read_header(mpq_fin)
            mpq.read_tables(mpq_fin)

            extract_mpq(mpq, mpq_fin, dest_dir)

    elif op == "create":
        src_dir = sys.argv[2]
        dest_fname = src_dir + ".w3x"

        with open(dest_fname, "wb") as fout_dest:
            mpq = MpqArchive()
            assemble_mpq(mpq, src_dir, fout_dest)

    elif op == "names":
        mpq = MpqArchive()
        for name in sys.argv[2:]:
            print("%30s: %04d %08X %08X" % (
                name,
                mpq.crypt.HashString(name, mpq.crypt.MPQ_HASH_TABLE_INDEX) % 4096,
                mpq.crypt.HashString(name, mpq.crypt.MPQ_HASH_NAME_A),
                mpq.crypt.HashString(name, mpq.crypt.MPQ_HASH_NAME_B)
            ))


if __name__ == "__main__":
    main()
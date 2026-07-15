import os
import sys
import struct
import traceback
import shutil
import re
import mmap
from pathlib import Path
# Noah , if you decompile this , please tell me if this line is ok for you : )
# With best Regards Harri Wailand (Palutenfan123)
print("Fixed by Palutenfan123 (timmkoo.de) ; )")

EXT4_HEADER_MAGIC = 0xED26FF3A
EXT4_SPARSE_HEADER_LEN = 28
EXT4_CHUNK_HEADER_SIZE = 12

# Optimal buffer sizes
COPY_BUFFER_SIZE = 1024 * 1024       # 1 MiB
FILE_READ_BUFFER_SIZE = 64 * 1024    # 64 KiB


class ProgressBar:
    def __init__(self, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.iteration = 0

    def print_progress(self, iteration=None):
        if iteration is not None:
            self.iteration = iteration
        percent = ("{0:." + str(self.decimals) + "f}").format(
            100 * (self.iteration / float(self.total))
        )
        filled_length = int(self.length * self.iteration // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        print(f'\r{self.prefix} |{bar}| {percent}% {self.suffix}', end='\r')
        if self.iteration == self.total:
            print()

    def increment(self, step=1):
        self.iteration += step
        self.print_progress()


class ext4_file_header(object):
    def __init__(self, buf):
        (self.magic,
         self.major,
         self.minor,
         self.file_header_size,
         self.chunk_header_size,
         self.block_size,
         self.total_blocks,
         self.total_chunks,
         self.crc32) = struct.unpack('<I4H4I', buf)


class ext4_chunk_header(object):
    def __init__(self, buf):
        (self.type,
         self.reserved,
         self.chunk_size,
         self.total_size) = struct.unpack('<2H2I', buf)


class Extractor(object):
    def __init__(self):
        self.FileName = ""
        self.BASE_DIR = ""
        self.OUTPUT_IMAGE_FILE = ""
        self.EXTRACT_DIR = ""
        self.BLOCK_SIZE = 4096
        self.TYPE_IMG = 'system'
        self.context = []
        self.fsconfig = []
        self.file_count = 0
        self.dir_count = 0
        self.link_count = 0

    def __remove(self, path):
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        else:
            raise ValueError(f"file {path} is not a file or dir.")

    def __logtb(self, ex, ex_traceback=None):
        if ex_traceback is None:
            ex_traceback = ex.__traceback__
        tb_lines = [
            line.rstrip('\n')
            for line in traceback.format_exception(
                ex.__class__, ex, ex_traceback
            )
        ]
        return '\n'.join(tb_lines)

    def __file_name(self, file_path):
        name = os.path.basename(file_path).split('.')[0]
        name = name.split('-')[0]
        name = name.split(' ')[0]
        name = name.split('+')[0]
        name = name.split('{')[0]
        name = name.split('(')[0]
        return name

    def __appendf(self, msg, log_file):
        with open(log_file, 'a', newline='\n', encoding='utf-8') as file:
            print(msg, file=file)

    def __getperm(self, arg):
        if len(arg) < 9 or len(arg) > 10:
            return
        if len(arg) > 8:
            arg = arg[1:]
        oor, ow, ox, gr, gw, gx, wr, ww, wx = list(arg)
        o, g, w, s = 0, 0, 0, 0
        if oor == 'r': o += 4
        if ow == 'w': o += 2
        if ox == 'x': o += 1
        if ox == 'S': s += 4
        if ox == 's': s += 4; o += 1
        if gr == 'r': g += 4
        if gw == 'w': g += 2
        if gx == 'x': g += 1
        if gx == 'S': s += 2
        if gx == 's': s += 2; g += 1
        if wr == 'r': w += 4
        if ww == 'w': w += 2
        if wx == 'x': w += 1
        if wx == 'T': s += 1
        if wx == 't': s += 1; w += 1
        return str(s) + str(o) + str(g) + str(w)

    def __ext4extractor(self):
        import ext4
        import string
        fs_config_file = os.path.join(self.BASE_DIR, self.FileName + '_fs_config')
        contexts = os.path.join(self.BASE_DIR, self.FileName + '_file_contexts')
        spaces_file = os.path.join(self.BASE_MYDIR, self.FileName + '_space.txt')

        os.makedirs(self.BASE_MYDIR, exist_ok=True)
        Path(spaces_file).touch(exist_ok=True)

        def scan_dir(root_inode, root_path=""):
            for entry_name, entry_inode_idx, entry_type in root_inode.open_dir():
                if (
                    entry_name in ['.', '..']
                    or entry_name.endswith(' (2)')
                    or entry_name == 'lost+found'
                ):
                    continue
                entry_inode = root_inode.volume.get_inode(entry_inode_idx, entry_type)
                entry_inode_path = root_path + '/' + entry_name
                mode = self.__getperm(entry_inode.mode_str)
                uid = entry_inode.inode.i_uid
                gid = entry_inode.inode.i_gid
                con = ''
                cap = ''
                for i in list(entry_inode.xattrs()):
                    if i[0] == 'security.selinux':
                        con = i[1].decode('utf8')[:-1]
                    elif i[0] == 'security.capability':
                        raw_cap = struct.unpack("<5I", i[1])
                        if raw_cap[1] > 65535:
                            cap = ' ' + str(hex(int('%04x%04x' % (raw_cap[3], raw_cap[1]), 16)))
                        else:
                            cap = ' ' + str(
                                hex(int('%04x%04x%04x' % (raw_cap[3], raw_cap[2], raw_cap[1]), 16))
                            )
                        cap = f' capabilities={cap}'

                original_path = self.DIR + entry_inode_path
                has_space = ' ' in original_path
                if has_space:
                    self.__appendf(original_path, spaces_file)
                fs_path = original_path.replace(' ', '_')

                # Strip leading '/' for relative path
                rel_path = entry_inode_path.lstrip('/')

                if entry_inode.is_dir:
                    print(f'[INFO] Creating directory: {entry_inode_path}')
                    dir_target = os.path.join(self.EXTRACT_DIR, rel_path)
                    os.makedirs(dir_target, exist_ok=True)
                    if os.name == 'posix':
                        os.chmod(dir_target, int(mode, 8))
                        os.chown(dir_target, uid, gid)
                    self.dir_count += 1
                    scan_dir(entry_inode, entry_inode_path)

                    line = f'{fs_path} {uid} {gid} {mode}'
                    if cap:
                        line += cap
                    self.fsconfig.append(line)

                    if con and con != f'u:object_r:{dirr}_file:s0':
                        self.context.append(f'/{fs_path} {con}')

                elif entry_inode.is_file:
                    print(f'[INFO] Extracting file: {entry_inode_path}')
                    file_target = os.path.join(self.EXTRACT_DIR, rel_path)
                    os.makedirs(os.path.dirname(file_target), exist_ok=True)

                    # ---- FIX: manually handle the reader, no context manager ----
                    src = entry_inode.open_read()
                    try:
                        with open(file_target, 'wb') as dst:
                            shutil.copyfileobj(src, dst, length=FILE_READ_BUFFER_SIZE)
                    finally:
                        if hasattr(src, 'close'):
                            src.close()
                    # -----------------------------------------------------------------

                    if os.name == 'posix':
                        os.chmod(file_target, int(mode, 8))
                        os.chown(file_target, uid, gid)
                    self.file_count += 1

                    line = f'{fs_path} {uid} {gid} {mode}'
                    if cap:
                        line += cap
                    self.fsconfig.append(line)

                    if con and con != f'u:object_r:{dirr}_file:s0':
                        self.context.append(f'/{fs_path} {con}')

                elif entry_inode.is_symlink:
                    try:
                        link_target = entry_inode.open_read().read().decode("utf8")
                    except Exception:
                        try:
                            link_target_block = int.from_bytes(
                                entry_inode.open_read().read(), "little"
                            )
                            link_target = root_inode.volume.read(
                                link_target_block * root_inode.volume.block_size,
                                entry_inode.inode.i_size,
                            ).decode("utf8")
                        except Exception:
                            link_target = ""
                    if not link_target or not all(c in string.printable for c in link_target):
                        continue

                    print(f'[INFO] Creating symlink: {entry_inode_path} -> {link_target}')
                    target = os.path.join(self.EXTRACT_DIR, rel_path)
                    if os.path.islink(target) or os.path.isfile(target):
                        try:
                            os.remove(target)
                        except OSError:
                            pass

                    if os.name == 'posix':
                        os.symlink(link_target, target)
                    elif os.name == 'nt':
                        with open(target.replace('/', os.sep), 'wb') as out:
                            tmp = bytes.fromhex('213C73796D6C696E6B3EFFFE')
                            for ch in link_target:
                                tmp += struct.pack('>sx', ch.encode('utf-8'))
                            out.write(tmp + struct.pack('xx'))
                        os.system(f'attrib +s "{target.replace("/", os.sep)}"')
                    self.link_count += 1

                    line = f'{fs_path} {uid} {gid} {mode}'
                    if cap:
                        line += cap
                    line += f' {link_target}'
                    self.fsconfig.append(line)

                    if con and con != f'u:object_r:{dirr}_file:s0':
                        self.context.append(f'/{fs_path} {con}')

        print('[INFO] Starting file extraction...')

        with open(os.path.join(self.BASE_DIR, self.FileName + '_size.txt'), 'w', encoding='utf-8') as f:
            f.write(str(os.path.getsize(self.OUTPUT_IMAGE_FILE)))

        with open(self.OUTPUT_IMAGE_FILE, 'rb') as file:
            root = ext4.Volume(file).root
            dirr = self.__file_name(os.path.basename(self.OUTPUT_IMAGE_FILE).split('.')[0])
            self.DIR = dirr

            # Base fs_config entries
            if dirr in ('system', 'vendor'):
                self.fsconfig = [f'{dirr}/lost+found 0 0 0700']
            else:
                self.fsconfig = []

            # Base SELinux context rule
            self.context = [f'/{dirr}(/.*)? u:object_r:{dirr}_file:s0']

            scan_dir(root)

            # Write fs_config
            self.fsconfig.sort()
            with open(fs_config_file, 'w', encoding='utf-8', newline='\n') as f:
                f.write('\n'.join(self.fsconfig))
            print(f'[INFO] Written {os.path.basename(fs_config_file)}')

            # Write file_contexts
            if self.context:
                self.context.sort()
                with open(contexts, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(self.context))
                print(f'[INFO] Written {os.path.basename(contexts)}')
            else:
                print('[INFO] No additional SELinux contexts found.')

        print(
            f'[INFO] Extraction summary: {self.file_count} files, '
            f'{self.dir_count} directories, {self.link_count} symlinks'
        )

    def is_valid_sparse_header(self, header):
        """
        Perform sanity checks on a parsed sparse header to avoid
        mistaking a raw ext4 image for a sparse one.
        """
        # Major version is usually 1, minor 0
        if header.major not in (0, 1) or header.minor != 0:
            return False
        # file header size must be >= 28 and reasonable
        if header.file_header_size < 28 or header.file_header_size > 4096:
            return False
        # chunk header size must be >= 12 and <= file_header_size
        if header.chunk_header_size < 12 or header.chunk_header_size > header.file_header_size:
            return False
        # block size should be a power of two between 512 and 65536
        if header.block_size < 512 or header.block_size > 65536:
            return False
        if (header.block_size & (header.block_size - 1)) != 0:
            return False
        # total blocks and chunks must be positive
        if header.total_blocks <= 0 or header.total_chunks <= 0:
            return False
        return True

    def __converSimgToImg(self, target):
        print(f'[INFO] Converting sparse image to raw image: {os.path.basename(target)}')
        with open(target, "rb") as img_file:
            if self.sign_offset > 0:
                img_file.seek(self.sign_offset, 0)
            header_buf = img_file.read(EXT4_SPARSE_HEADER_LEN)
            header = ext4_file_header(header_buf)
            total_chunks = header.total_chunks

            if header.file_header_size > EXT4_SPARSE_HEADER_LEN:
                img_file.seek(header.file_header_size - EXT4_SPARSE_HEADER_LEN, 1)

            raw_img_path = target.replace(".img", ".raw.img")
            progress = ProgressBar(total_chunks, prefix='Progress', suffix='Complete', length=40)

            with open(raw_img_path, "wb") as raw_img_file:
                sector_base = 82528  # legacy compatibility
                while total_chunks > 0:
                    chunk_header_buf = img_file.read(header.chunk_header_size)
                    if len(chunk_header_buf) < EXT4_CHUNK_HEADER_SIZE:
                        raise RuntimeError("Unexpected end of file while reading chunk header")
                    chunk_header = ext4_chunk_header(chunk_header_buf[:EXT4_CHUNK_HEADER_SIZE])
                    # extra bytes after standard 12 are just padding; already read

                    sector_size = (chunk_header.chunk_size * header.block_size) >> 9
                    chunk_data_size = chunk_header.total_size - header.chunk_header_size

                    if chunk_header.type == 0xCAC1:  # RAW
                        remaining = chunk_data_size
                        while remaining > 0:
                            to_read = min(COPY_BUFFER_SIZE, remaining)
                            data = img_file.read(to_read)
                            if not data:
                                break
                            raw_img_file.write(data)
                            remaining -= len(data)
                        sector_base += sector_size

                    elif chunk_header.type in (0xCAC2, 0xCAC3, 0xCAC4):  # FILL, DONTCARE, CRC32
                        if chunk_data_size > 0:
                            img_file.seek(chunk_data_size, 1)
                        if chunk_header.type == 0xCAC2:  # FILL: zero out
                            zero_bytes = sector_size << 9
                            remaining_zeros = zero_bytes
                            while remaining_zeros > 0:
                                write_now = min(COPY_BUFFER_SIZE, remaining_zeros)
                                raw_img_file.write(b'\x00' * write_now)
                                remaining_zeros -= write_now
                        elif chunk_header.type == 0xCAC3:  # DONTCARE
                            raw_img_file.seek(sector_size << 9, 1)
                        # CRC32 (0xCAC4) – no output needed
                        sector_base += sector_size

                    else:
                        raise ValueError(
                            f"Unknown chunk type: {chunk_header.type:#x}. "
                            "The image may not be a valid Android sparse image."
                        )

                    total_chunks -= 1
                    progress.increment()

        self.OUTPUT_IMAGE_FILE = raw_img_path
        print(f'[INFO] Raw image saved as: {raw_img_path}')

    def fixmoto(self, input_file):
        print(f'[INFO] Checking for MOTO header in {input_file}...')
        if not os.path.exists(input_file):
            return
        output_file = input_file + "_"
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except OSError:
                pass
        with open(input_file, 'rb') as f:
            data = f.read(500000)
        if not re.search(b'\x4d\x4f\x54\x4f', data):
            print('[INFO] No MOTO header found.')
            return
        print('[INFO] MOTO header found, fixing...')
        result = []
        for i in re.finditer(b'\x53\xEF', data):
            result.append(i.start() - 1080)
        offset = 0
        for i in result:
            if data[i] == 0:
                offset = i
                break
        if offset > 0:
            with open(output_file, 'wb') as o, open(input_file, 'rb') as f:
                f.seek(offset)
                data = f.read(15360)
                if data:
                    o.write(data)
        try:
            os.remove(input_file)
            os.rename(output_file, input_file)
            print('[INFO] MOTO fix applied.')
        except OSError:
            print('[WARN] Could not replace original file with fixed version.')

    def checkSignOffset(self, file):
        size = os.stat(file.name).st_size
        if size <= 52428800:
            mm = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            mm = mmap.mmap(file.fileno(), 52428800, access=mmap.ACCESS_READ)
        offset = mm.find(struct.pack('<L', EXT4_HEADER_MAGIC))
        mm.close()
        return offset

    def __getTypeTarget(self, target):
        """Determine whether the image is Android sparse or raw ext4."""
        _, file_extension = os.path.splitext(target)
        if file_extension != '.img':
            return 'img'

        with open(target, "rb") as img_file:
            self.sign_offset = self.checkSignOffset(img_file)
            if self.sign_offset < 0:
                return 'img'
            img_file.seek(self.sign_offset, 0)
            header_buf = img_file.read(EXT4_SPARSE_HEADER_LEN)
            if len(header_buf) < EXT4_SPARSE_HEADER_LEN:
                return 'img'
            try:
                header = ext4_file_header(header_buf)
            except struct.error:
                return 'img'

            if header.magic != EXT4_HEADER_MAGIC:
                return 'img'
            if not self.is_valid_sparse_header(header):
                print("[WARN] Sparse header found but it looks invalid – treating as raw image.")
                return 'img'
            # Quick check: first chunk type
            if header.file_header_size > EXT4_SPARSE_HEADER_LEN:
                img_file.seek(header.file_header_size - EXT4_SPARSE_HEADER_LEN, 1)
            first_chunk = img_file.read(header.chunk_header_size)
            if len(first_chunk) < EXT4_CHUNK_HEADER_SIZE:
                return 'img'
            chunk = ext4_chunk_header(first_chunk[:EXT4_CHUNK_HEADER_SIZE])
            if chunk.type not in (0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4):
                print(f"[WARN] First chunk type {chunk.type:#x} is unknown – treating as raw image.")
                return 'img'
            return 'simg'

    def main(self, target, output_dir):
        print(f'[INFO] Processing image: {target}')
        target = os.path.abspath(target)
        output_dir = os.path.abspath(output_dir)

        self.BASE_DIR = output_dir + os.sep
        self.BASE_MYDIR = output_dir + os.sep
        self.EXTRACT_DIR = output_dir
        self.OUTPUT_IMAGE_FILE = target
        self.FileName = self.__file_name(os.path.basename(target))

        target_type = self.__getTypeTarget(target)
        print(f'[INFO] Image type: {"sparse" if target_type == "simg" else "raw"}')

        if target_type == 'simg':
            self.__converSimgToImg(target)
            with open(self.OUTPUT_IMAGE_FILE, 'rb') as f:
                data = f.read(500000)
            if re.search(b'\x4d\x4f\x54\x4f', data):
                self.fixmoto(os.path.abspath(self.OUTPUT_IMAGE_FILE))
            print(f'[INFO] Extracting to: {self.EXTRACT_DIR}')
            self.__ext4extractor()
        else:
            with open(os.path.abspath(self.OUTPUT_IMAGE_FILE), 'rb') as f:
                data = f.read(500000)
            if re.search(b'\x4d\x4f\x54\x4f', data):
                self.fixmoto(os.path.abspath(self.OUTPUT_IMAGE_FILE))
            print(f'[INFO] Extracting to: {self.EXTRACT_DIR}')
            self.__ext4extractor()

        print(f'[INFO] Done! All files and configs are in: {self.EXTRACT_DIR}')


if __name__ == '__main__':
    if len(sys.argv) == 3:
        base_out = sys.argv[2]
        img_name = os.path.basename(sys.argv[1]).split('.')[0]
        out = os.path.join(base_out, img_name)
        Extractor().main(sys.argv[1], out)
    elif len(sys.argv) == 2:
        image_path = sys.argv[1]
        image_name = os.path.basename(image_path).split('.')[0]
        out = os.path.join(os.path.dirname(os.path.abspath(image_path)), image_name)
        Extractor().main(image_path, out)
    else:
        print("Usage:imgextractor.exe <image.img> [output_config_dir]")
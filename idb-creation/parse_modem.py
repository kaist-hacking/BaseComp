import os
import struct
import lz4.frame
import time

try:
    from idc import LoadFile, get_idb_path
    from ida_segment import add_segm, get_segm_by_name, getseg, set_segm_name
    from ida_auto import auto_make_code, auto_wait

    USE_IDA = True
except:
    USE_IDA = False


def u32(data):
    return struct.unpack("<I", data)[0]


class ModemChunk(object):
    def __init__(self, fname, data):
        assert len(data) == 32
        self.name = data[0:4].rstrip(b'\x00').decode()
        self.offset = u32(data[12:16])
        self.vaddr = u32(data[16:20])
        self.size = u32(data[20:24])
        self.index = u32(data[28:32])
        self.fname = fname

    def store_chunk(self):
        with open(self.fname, 'rb') as f:
            f.seek(self.offset)
            data = f.read(self.size)

        out_dir = os.path.dirname(self.fname)
        base_name = os.path.basename(self.fname)
        out_fname = os.path.join(
            out_dir,
            '_'.join(
                [base_name,
                 str(self.index),
                 str(self.name),
                 hex(self.offset),
                 hex(self.vaddr),
                 hex(self.size)]))

        with open(out_fname, 'wb') as f:
            f.write(data)

    def load_chunk(self):
        if self.vaddr == 0:
            return
        if self.name not in ['BOOT', 'MAIN', b'BOOT', b'MAIN']:
            return
        if get_segm_by_name(self.name):
            print("Already existing segment: %s" % (str(self)))

        else:
            print("Allocating new segment: %s" % (str(self)))
            # del_segm(self.vaddr, 0)
            add_segm(0, self.vaddr, self.vaddr + self.size, self.name, "CODE")
            LoadFile(self.fname, self.offset, self.vaddr, self.size)
            if self.name in ['BOOT', 'MAIN']:
                # auto_make_code(self.vaddr)
                auto_wait()

    def __str__(self):
        return "%s, 0x%x -> 0x%x, size: 0x%x" % (self.name,
                                                 self.vaddr, self.vaddr + self.size, self.size)


if 'chunk_list' not in globals():
    chunk_list = []


def parse_chunks(fname):
    global chunk_list
    print(fname)
    if fname.endswith('.lz4'):
        with open(fname, 'rb') as f:
            data = f.read()
        fname = fname.replace('.lz4', '')
        with open(fname, 'wb') as f:
            data = lz4.frame.decompress(data)
            f.write(data)
            data = data[:8192]
    else:
        with open(fname, 'rb') as f:
            data = f.read(8192)

    idx = 0
    while idx < len(data):
        tmp_data = data[idx:idx + 32]
        if tmp_data[0] == 0x00:
            break
        print(tmp_data)
        chunk = ModemChunk(fname, tmp_data)
        chunk_list.append(chunk)
        if USE_IDA:
            print(chunk)
            chunk.load_chunk()
        else:
            print(chunk)
            chunk.store_chunk()
        idx += 32


times = []
funcs = []

def init_all():
    global times, funcs
    from scatter import run_scatterload
    import analyze_data_struct
    import find_dbgsym
    from utils import is_main
    from idautils import Functions
    auto_wait()

    start_time = time.time()
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    run_scatterload()
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    find_dbgsym.init_dbt()
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    analyze_data_struct.init_functions()
    times.append(analyze_data_struct.FUNC_BY_LS_TIME)
    funcs.append(analyze_data_struct.FUNC_BY_LS)
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))
    times.append(analyze_data_struct.FUNC_BY_PTR_TIME)
    funcs.append(analyze_data_struct.FUNC_BY_PTR)
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    analyze_data_struct.init_strings()
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    find_dbgsym.analyze_dbt()
    times.append(find_dbgsym.FUNC_BY_DBT_TIME)
    funcs.append(find_dbgsym.FUNC_BY_DBT)
    times.append(find_dbgsym.XREFS_BY_DBT_TIME)
    funcs.append(list(map(lambda x: x[0], find_dbgsym.XREFS_BY_DBT)))
    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    names = ['initial', 'scatterload', 'init_dbt',
             'linear_sweep', 'linear_sweep+ida',
             'pointer_analysis', 'init_functions',
             'init_strings',
             'dbt_func_analysis', 'dbt_xref_analysis', 'analyze_dbt']

    times.append(time.time() - start_time)
    funcs.append(list(Functions()))

    names = ['initial', 'scatterload', 'init_dbt',
             'linear_sweep', 'linear_sweep+ida',
             'pointer_analysis', 'init_functions',
             'init_strings',
             'dbt_func_analysis', 'dbt_xref_analysis', 'analyze_dbt',
            ]

    print('Procedure,# of Funcs,# of Main Funcs,Time')
    for idx in range(len(names)):
        func_num = len(funcs[idx])
        main_func_num = len(list(filter(lambda x: is_main(x), funcs[idx])))
        print('{},{},{},{:.3f}'.format(names[idx], func_num, main_func_num, times[idx]))


if USE_IDA:
    # init_all()
    dir_name = os.path.dirname(get_idb_path())
    fname = os.path.join(dir_name, 'modem.bin')
    if not os.path.exists(fname):
        fname = ida_kernwin.ask_file(0, 'modem.bin', '.bin')
    parse_chunks(fname)

else:
    fname = input("Please input modem file path: ").strip()
    if os.path.isdir(fname):
        for root, dirs, files in os.walk(fname):
            for file in files:
                if 'modem' not in file:
                    continue
                if 'debug' in file:
                    continue
                if not file.endswith(".lz4") and not file.endswith(".bin"):
                    continue

                print('=' * 30)
                print(os.path.join(root, file))
                path = os.path.join(root, file)
                try:
                    parse_chunks(path)
                except:
                    print("Parsing {} failed ...".format(file))

    else:
        if 'modem' in fname and 'debug' not in fname and \
                (fname.endswith('.lz4') or fname.endswith('.bin')):
            parse_chunks(fname)

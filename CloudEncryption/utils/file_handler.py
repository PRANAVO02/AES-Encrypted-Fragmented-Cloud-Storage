import os
from config import FRAGMENT_FOLDER

def split_file_auto(file_path, base_fragment_size=1*1024*1024):
    os.makedirs(FRAGMENT_FOLDER, exist_ok=True)
    fragments = []
    file_size = os.path.getsize(file_path)

    if file_size <= 10*1024*1024:
        num_fragments = 4
    elif file_size <= 100*1024*1024:
        num_fragments = max(2, file_size // base_fragment_size)
    else:
        num_fragments = max(2, file_size // (5*1024*1024))

    fragment_size = file_size // num_fragments
    remainder = file_size % num_fragments

    with open(file_path, "rb") as f:
        for i in range(num_fragments):
            size = fragment_size + (remainder if i == num_fragments - 1 else 0)
            chunk = f.read(size)
            frag_name = os.path.join(FRAGMENT_FOLDER, f"{os.path.basename(file_path)}_frag_{i}")
            with open(frag_name, "wb") as frag:
                frag.write(chunk)
            fragments.append(frag_name)
    return fragments

def merge_fragments(fragments_list, output_path):
    with open(output_path, "wb") as outfile:
        for frag in fragments_list:
            with open(frag, "rb") as f:
                outfile.write(f.read())

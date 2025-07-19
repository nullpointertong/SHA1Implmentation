import itertools
import multiprocessing as mp
import time

class sha1_hash:
    #Rotate one bit to the left keeping the value to 32 bits
    @staticmethod
    def left_rotate(value, offset):
        return ((value << offset) & 0xFFFFFFFF) | (value >> (32 - offset))

    @staticmethod
    def generate(data):
        data = data.encode()

        #These are constant values set for SHA1 
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

        data_bit_len = len(data) * 8
        # append the '1' to the end of the byte as per the SHA1 spec(0x80 = 10000000)
        data += b"\x80"

        #Step 1 Pad and Split the data into 512 bit chunks
        while (len(data) * 8) % 512 != 448:
            #Add Padding if not cleanly breakable into 512 bits
            data += b"\x00"
        data += data_bit_len.to_bytes(8, 'big')

        # Step 2 Preprocess the data into 512-bit chunks
        for chunk_start in range(0, len(data), 64):
            bit_chunk = data[chunk_start : chunk_start + 64]

            #Step 2.a Convert chunks into 16 32-bit words with big endian order
            w = [int.from_bytes(bit_chunk[j : j + 4], 'big') for j in range(0, 64, 4)]

            #Step 2.b Extend the 16 words to 80 words 
            for j in range(16, 80):
                val = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]
                w.append(sha1_hash.left_rotate(val, 1))

            #Step 3 Initialize working variables
            a = h0 
            b = h1 
            c = h2 
            d = h3
            e = h4
            
            #Step 4 80 rounds of mixing
            for j in range(80):
                if j < 20:
                    # Step 4a choose bits from b, c, d
                    f = ((b & c) | (~b & d))
                    k = 0x5A827999
                elif j < 40:
                    # Step 4b XOR words together 
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif j < 60:
                    f = ((b & c) | (b & d) | (c & d))
                    k = 0x8F1BBCDC
                else:
                    # Step 4d again XOR words together
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                temp = (sha1_hash.left_rotate(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
                e = d 
                d = c 
                c = sha1_hash.left_rotate(b, 30) 
                b = a 
                a = temp
            
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF
        return ''.join(h.to_bytes(4, 'big').hex() for h in (h0, h1, h2, h3, h4))

# Globals to be set per worker
found_event = None
result_queue = None
target_hash_global = None


def verify_sha1(candidate_tuple):
    if found_event.is_set():
        return None
    text = ''.join(candidate_tuple)
    if sha1_hash.generate(text) == target_hash_global:
        try:
            result_queue.put(text)
        except Exception:
            pass
        found_event.set()
        return text
    return None

def init_worker(event, queue, target_hash):
    global found_event, result_queue, target_hash_global
    found_event = event
    result_queue = queue
    target_hash_global = target_hash

def find_sha1_plaintext(max_length, target_hash, charset='abcdefghijklmnopqrstuvwxyz0123456789'):
    # Manager for Event/Queue
    manager = mp.Manager()
    shared_event = manager.Event()
    shared_queue = manager.Queue()
    it = 0

    pool_size = max(1, mp.cpu_count() - 1)
    # Prepare Pool with initializer to set shared globals
    with mp.Pool(processes=pool_size,
                 initializer=init_worker,
                 initargs=(shared_event, shared_queue, target_hash)) as pool:

        try:
            start_time = time.time()
            for length in range(1, max_length + 1):
                # If already found, break
                if shared_event.is_set():
                    break
                # Generate an iterator of candidate tuples
                possible_candidates = itertools.product(charset, repeat=length)
                # We use imap_unordered to lazily schedule tasks in chunks
                chunksize = 10000
                for result in pool.imap_unordered(verify_sha1, possible_candidates, chunksize=chunksize):
                    it += 1
                    if(it % chunksize == 0):
                        print(f"Iterations/Steps: {it} Time: {time.time() - start_time:.2f}s")
                    if result is not None:
                        shared_event.set()
                        break
                    if shared_event.is_set():
                        break
                if shared_event.is_set():
                    break
            else:
                if not shared_event.is_set():
                    print("Target not found up to length", max_length)
            pool.terminate()
        finally:
            pool.join()

        if shared_event.is_set():
            try:
                result = shared_queue.get_nowait()
                print(f"Found target: {result} Iterations/Steps: {it} Time: {time.time() - start_time:.2f}s")
                return result
            except Exception:
                return None
        return None

if __name__ == "__main__":
    print("Please Enter a small string to hash and crack(Ideally less than 6 characters long and without any symbols, knowing that the characters will be cast to lower case): ")
    plaintext = input().lower()

    h = sha1_hash.generate(plaintext)
    print(f"SHA1({plaintext}) =", h)
    print(f"Cracking hash: {h}")

    # little hint so it doesn't run forever gives plaintext length as hint
    result = find_sha1_plaintext(len(plaintext), h)
    if result:
        print(f"Found match: {result}")
    else:
        print("No match found.")

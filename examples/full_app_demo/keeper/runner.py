"""This entire file could be loaded as a plugin or part of the existing vanity_finder plugin"""

import asyncio
import time
from concurrent.futures import ProcessPoolExecutor

from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import FluxMainnet
from hdwallet.utils import generate_mnemonic, is_mnemonic


def find_address(
    stop_event,
    update_queue,
    response_queue,
    bip44_hdwallet,
    prefix,
    derivation=[0, 10000],
):
    best = "t1"
    print("worker running...")
    # start = time.time()

    for address_index in range(*derivation):
        if stop_event.is_set():
            break

        # for this to work, need to enumerate the range, but slows down loop

        # if address_index % 1000 == 0:
        #     end = time.time()
        #     elapsed = end - start
        #     print(f"Hashes per second: {address_index / elapsed}")

        bip44_hdwallet.clean_derivation()
        bip44_hdwallet.from_path(f"m/44'/19167'/0'/0/{address_index}")
        address = bip44_hdwallet.p2pkh_address()

        matches = "t1"
        for index, char in enumerate(prefix):
            if address[index + 2] == char:
                matches += char
                if len(matches) > len(best):
                    best = matches
                    update_queue.put(best)
            else:
                break

        if address[0 : len(prefix) + 2] == f"t1{prefix}":
            response_queue.put(
                [address, bip44_hdwallet.path(), bip44_hdwallet.mnemonic()]
            )
            break


async def main(stop_event, update_queue, response_queue, cpu_count, passphrase, vanity):
    loop = asyncio.get_event_loop()

    strength = 160
    language = "english"
    mnemonic = generate_mnemonic(language=language, strength=strength)

    assert is_mnemonic(mnemonic=mnemonic, language=language)

    bip44_hdwallet = BIP44HDWallet(
        cryptocurrency=FluxMainnet, account=0, change=False, address=0
    )
    bip44_hdwallet.from_mnemonic(
        mnemonic=mnemonic, passphrase=passphrase, language=language
    )

    bip44_hdwallet.clean_derivation()

    chunks = []
    total = 250000
    chunk_size = total // cpu_count
    remainder = total % cpu_count

    print("Total", total)
    print("chunk size", chunk_size)
    print("remainder", remainder)

    start_time = time.time()

    executor = ProcessPoolExecutor(max_workers=cpu_count)
    for chunk in range(cpu_count):
        start = chunk * chunk_size
        end = start + chunk_size - 1
        if chunk == cpu_count - 1:
            end += remainder
        chunks.append([start, end])

    futures = [
        loop.run_in_executor(
            executor,
            find_address,
            stop_event,
            update_queue,
            response_queue,
            bip44_hdwallet,
            vanity,
            chunk,
        )
        for chunk in chunks
    ]

    print(f"Running on {len(futures)} cpus")

    done, running = await asyncio.wait(futures, return_when=asyncio.FIRST_COMPLETED)
    end_time = time.time()

    print("Completed futures count:", len(done))
    print("Elapsed:", end_time - start_time)

    for d in done:
        # result = d.result()

        for future in running:
            future.cancel()

        await asyncio.wait(running)

// SPDX-License-Identifier: LGPL-3.0-only
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#include <print>

#include "nfc.hpp"

using namespace nfcpp;
using namespace nfcpp::mifare;
using namespace nfcpp::util;

template <std::size_t N>
using data_parity = NfcTransmitDataAutoParity<N>;

template <std::size_t N>
using data_crc_parity = NfcTransmitDataAutoCRCParity<N, NfcCRC::ISO14443A>;

int main(int argc, char* argv[]) try {
    NfcContext context;

    auto device = context.open_device();
    std::println("NFC device opened: {}", device->get_name());

    auto initiator = device->as_initiator();
    auto driver    = device->get_driver<NfcPN53xDriver>();

    auto target = initiator->select_passive_target(NfcCard::MifareClassic1K);

    auto target_info = target.get_info<NfcISO14443ATargetInfo>();
    auto nuid        = target_info->nuid();

    std::println("Uid: {}", hex(nuid));

    device->set_property(NP_EASY_FRAMING, false);
    device->set_property(NP_HANDLE_CRC, false);
    device->set_property(NP_HANDLE_PARITY, false);

    constexpr auto SECTOR_ADDR = 0x00;
    constexpr auto KEY_A       = 0xFFFFFFFFFFFF;

    // [R -> T] Request plaintext nonce. (Nt)

    NfcReceiveData<uint32_t> nt_r;
    initiator->transceive_bits(data_crc_parity(MC_AUTH_A, SECTOR_ADDR), nt_r);

    // [T -> R] Answer plaintext nonce.
    //          Each initializes its Crypto1 state.

    auto nt = *nt_r.as_big_endian();

    std::println("Nt:  {}", hex(std::byteswap(nt)));

    MifareCrypto1Cipher cipher(KEY_A);
    cipher.word(nuid ^ nt, false);

    // [R -> T] Construct and send reader answer. (Ar)

    std::array<uint8_t, 8> ar{}; // 4 bytes (Nr) + 4 bytes (Ntt)

    nt = prng_successor(nt, 32);
    for (auto i : std::views::iota(4, 8)) {
        nt    = prng_successor(nt, 8);
        ar[i] = nt & 0xff;
    }

    std::println("Ar:  {}", hex(ar));

    NfcReceiveData<uint32_t> at_r;
    initiator->transceive_bits(
        data_parity(ar).with_encrypt(
            cipher,
            [](auto&& cipher) {
                cipher.crypt_feed(4);
                cipher.crypt(4);
            }
        ),
        at_r
    );

    // [T -> R] Tag answer and reader verification.
    //          Authentication completed.

    auto at = *at_r.as_big_endian().as_decrypted(cipher, false, false);

    std::println("At:  {}", hex(std::byteswap(at)));

    nt = prng_successor(nt, 32);
    if (at == nt) {
        std::println("Authentication completed.");
    }

    return 0;
} catch (const std::runtime_error& e) {
    std::println("<RUNTIME ERROR> {}", e.what());
    return 1;
}

## NFC++

nfcpp is a [libnfc](https://github.com/nfc-tools/libnfc) wrapper library, which uses C++23 best practices.

## Features

- Header-only & Single-file. _(Mostly)_
- Commonly used operations are encapsulated.
- Exception-safety.

## Get started

#### 1. Deploy to your project.

First, I must explain why this library is _mostly_ a header-only single-file library.

- The library itself only contains [`nfc.hpp`](https://github.com/Redbeanw44602/nfcpp/blob/main/src/nfc.hpp)
- You still need to handle libnfc compilation/linking. - _I'm just a wrapper._
- Because some header files are missing in the default libnfc installation, [`nfc-extra`](https://github.com/Redbeanw44602/nfcpp/tree/main/src/nfc-extra) is **required**.
- If you require crypto functionality for Mifare Classic cards, you will also need the [`crapto1`](https://github.com/Redbeanw44602/nfcpp/tree/main/src/crapto1) library.

> [!IMPORTANT]
> Please continue reading for details on enabling crapto1 features.

For non-buildsystem projects.

- First, import libnfc in a reasonable way (details omitted).
- Please `git checkout` to the latest release.
- Move files under the `src` directory, at least requires `nfc.hpp`, `nfc-extra/`.

For non-xmake projects.

- **_TODO_** I will provide a reasonable import method for cmake/meson as soon as possible.

For xmake projects.

- **_TODO_** I wil submit this package to xrepo as soon as possible.

```lua
add_requires('nfcpp')

target('dummy')
    add_packages('nfcpp')
    ...
```

#### 2. Include it from the souce.

You only need to...

```cpp
#include <nfc.hpp>

// It is recommended to use `using` to avoid overly long names, most classes in
// nfcpp begin with `Nfc`, so name conflicts are generally not a problem.

using namespace nfcpp;
using namespace nfcpp::mifare;    // Provides `MifareCrypto1Cipher`.
using namespace nfcpp::util;      // Some utilities may contain common names. (!)
```

That's great! It will bring in everything you need.

#### 3. Try a simple demo.

The complete source code for the demo is [here](https://github.com/Redbeanw44602/nfcpp/tree/main/examples/mifare_auth).

To avoid making the README too complicated, I have omitted many common things (such as `include`/`using namespace`/`select_passive_targets`...) and only kept what I thought was valuable.

A key feature of nfcpp is its support for transforming bitstreams (or bytestreams) to be transmitted at compile time (or runtime). This is supported by the `NfcTransmitData` template and several useful transformers is included by default; you will learn more in the documentation.

The following shows two commonly used transformers that add CRC or calculate parity for the input data. To avoid excessively long names, it is recommended to `using` them.

```cpp
template <std::size_t N>
using data_parity = NfcTransmitDataAutoParity<N>;

template <std::size_t N>
using data_crc_parity = NfcTransmitDataAutoCRCParity<N, NfcCRC::ISO14443A>;
```

Then, we will implement Mifare Classic Auth in pure software, with the card reader only transmitting the bitstream.

```cpp
auto device    = context.open_device();
auto initiator = device->as_initiator();

// The sector number and key to be authenticate.
constexpr auto SECTOR_ADDR = 0x00;
constexpr auto KEY_A       = 0xFFFFFFFFFFFF;

// [R -> T] Request plaintext nonce. (Nt)
NfcReceiveData<uint32_t> nt_r;
initiator->transceive_bits(data_crc_parity(MC_AUTH_A, SECTOR_ADDR), nt_r);

// [T -> R] Answer plaintext nonce.
//          Each initializes its Crypto1 state.
auto nt = *nt_r.as_big_endian();

MifareCrypto1Cipher cipher(KEY_A);
cipher.word(nuid ^ nt, false);

// [R -> T] Construct and send reader answer. (Ar)
std::array<uint8_t, 8> ar{}; // 4 bytes (Nr) + 4 bytes (Ntt)

nt = prng_successor(nt, 32);
for (size_t i = 4; i < 8; i++) {
    nt    = prng_successor(nt, 8);
    ar[i] = nt & 0xff;
}

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

nt = prng_successor(nt, 32);
if (at == nt) {
    std::println("Authentication completed.");
}
```

It's easy, isn't it? Only about 50 lines. Thanks to the power of nfcpp, you can enjoy the convenience without losing control over every bit, which is especially useful when writing RFID security tools.

## Enable crypto1 feature

The crypto1 implementation used by nfcpp comes from [proxmark3](https://github.com/RfidResearchGroup/proxmark3), which is licensed under GPLv3.

To enable this feature, build nfcpp with following option.

```bash
xmake f --crapto1=true
xmake build
```

This will automatically build the crapto1 library and enable all crypto1 features in `nfc.hpp` (via defines `NFCPP_ENABLE_CRAPTO1=1`).

> [!CAUTION]
> With crapto1 enabled, this library is now subject to the GPLv3 license.

## Documentation

**_TODO_**

## License

LGPLv3 by default, GPLv3 if crapto1 is used.

// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2026-present, RedbeanW.
 * This file is part of the NFC++ open source project.
 */

#pragma once

#include <algorithm>
#include <concepts>
#include <cstring>
#include <memory>
#include <ranges>
#include <vector>

#include <format>
#include <print>

#include <nfc/nfc.h>

#include "nfc-extra/mifare.h"         // IWYU pragma: export
#include "nfc-extra/pn53x-internal.h" // IWYU pragma: export
#include "nfc-extra/pn53x.h"          // IWYU pragma: export

#if NFCPP_ENABLE_CRAPTO1
#include "crapto1/crapto1.h" // IWYU pragma: export
#endif

#define NFCPP_LIBNFC_ENSURE(result)                                            \
    if (result < 0) {                                                          \
        char buffer[1024];                                                     \
        nfc_strerror_r(&*m_device, buffer, sizeof(buffer));                    \
        throw NfcException(static_cast<NfcError>(result), buffer);             \
    }

namespace nfcpp {

enum class NfcCard {
    Mifare,
};

enum class NfcCRC {
    ISO14443A,
    ISO14443B,
};

enum class NfcError {
    // Success(no error)
    SUCCESS = 0,
    // Input / output error, device may not be usable anymore without re-open it
    IO = -1,
    // Invalid argument(s)
    INVARG = -2,
    //  Operation not supported by device
    DEVNOTSUPP = -3,
    // No such device
    NOTSUCHDEV = -4,
    // Buffer overflow
    OVFLOW = -5,
    // Operation timed out
    TIMEOUT = -6,
    // Operation aborted (by user)
    OPABORTED = -7,
    // Not (yet) implemented
    NOTIMPL = -8,
    // Target released
    TGRELEASED = -10,
    // Error while RF transmission
    RFTRANS = -20,
    // MIFARE Classic: authentication failed
    MFCAUTHFAIL = -30,
    // Software error (allocation, file/pipe creation, etc.)
    SOFT = -80,
    // Device's internal chip error
    CHIP = -90
};

class NfcContext;
class NfcDevice;

namespace detail {

template <typename T>
concept TriviallyCopyable = std::is_trivially_copyable_v<T>;

template <typename F, typename R, typename... Args>
concept Callable = std::invocable<F, Args...>
                && std::convertible_to<std::invoke_result_t<F, Args...>, R>;

template <typename T, typename R>
concept HasGetter = requires(T t) {
    { t.get() } -> std::convertible_to<R>;
};

template <typename T>
concept HasExpand =
    requires { typename std::integral_constant<std::size_t, T::expand(1)>; };

template <typename T>
concept HasApply =
    requires(std::span<std::uint8_t, T::expand(1)> input) { T::apply(input); };

template <typename T>
concept HasApplyParity =
    requires(std::span<std::uint8_t, 1> input) { T::apply_parity(input); };

template <typename T>
concept IsByte = std::convertible_to<T, std::uint8_t>;

template <typename T>
concept IsByteRange =
    std::ranges::contiguous_range<T>
    && std::convertible_to<std::ranges::range_value_t<T>, std::uint8_t>;

template <typename T>
concept HasReadableByteSpan = HasGetter<const T, std::span<const std::uint8_t>>;

template <typename T>
concept HasMutableByteSpan = HasGetter<T, std::span<std::uint8_t>>;

template <typename F>
concept IsParityCalculator = Callable<F, void, std::span<std::uint8_t, 1>>;

template <typename T>
concept HasParityCalculator = requires() { typename T::parity_calculator; }
                           && IsParityCalculator<typename T::parity_calculator>;

template <typename T>
concept HasParityGetter = requires(T t) {
    { t.get_parity() } -> std::convertible_to<std::span<const std::uint8_t>>;
};

template <typename T>
concept IsNfcTransmitDataTransformer = HasApply<T> || HasApplyParity<T>;

template <typename T>
concept IsNfcTargetInfo = std::constructible_from<T, nfc_target_info*>;

template <typename T>
concept IsByteOrByteRange = IsByte<T> || IsByteRange<T>;

template <typename T>
struct IsStdSpanImpl : std::false_type {};

template <typename T, std::size_t E>
struct IsStdSpanImpl<std::span<T, E>> : std::true_type {};

template <typename T>
concept IsStdSpan = IsStdSpanImpl<std::remove_cvref_t<T>>::value;

template <typename T>
struct IsStdArrayImpl : std::false_type {};

template <typename T, std::size_t N>
struct IsStdArrayImpl<std::array<T, N>> : std::true_type {};

template <typename T>
concept IsStdArray = IsStdArrayImpl<std::remove_cvref_t<T>>::value;

template <typename T>
concept IsStaticExtentStdSpan =
    IsStdSpan<T> && T::extent != std::dynamic_extent;

template <typename T>
concept IsCStyleArrayBytes =
    std::is_bounded_array_v<T> && std::rank_v<T> == 1
    && std::convertible_to<std::remove_extent_t<T>, std::uint8_t>;

template <typename T>
concept IsStdArrayBytes =
    detail::IsStdArray<T>
    && std::convertible_to<typename T::value_type, std::uint8_t>;

template <typename T>
concept IsStaticExtentStdSpanBytes =
    detail::IsStaticExtentStdSpan<T>
    && std::convertible_to<typename T::element_type, std::uint8_t>;

template <typename T>
using Ptr = T*;

template <typename T>
using OptionalRef = std::optional<std::reference_wrapper<T>>;

template <bool Enabled, std::size_t Size>
struct ParityStorage;

template <std::size_t Size>
struct ParityStorage<false, Size> {
    template <typename T>
    constexpr explicit ParityStorage(T&&) {}
};

template <std::size_t Size>
struct ParityStorage<true, Size> {
    constexpr explicit ParityStorage(std::array<std::uint8_t, Size>&& data)
    : m_data(data) {}

    constexpr auto get(this auto& self) { return std::span(self.m_data); }

private:
    std::array<std::uint8_t, Size> m_data{};
};

template <std::size_t Base, IsNfcTransmitDataTransformer... Ts>
consteval auto compute_nfc_transmit_data_size() {
    std::size_t ret = Base;

    (
        [&] {
            if constexpr (HasExpand<Ts>) {
                ret = Ts::expand(ret);
            }
        }(),
        ...
    );

    return ret;
}

template <
    std::size_t Base,
    std::size_t FnSize,
    IsNfcTransmitDataTransformer... Ts>
    requires(FnSize >= Base)
constexpr auto
transform_nfc_transmit_data(std::span<const std::uint8_t, Base> input) {
    std::array<std::uint8_t, FnSize> ret;
    [[maybe_unused]] std::size_t     current_size = Base;

    // The Base size may not match FnSize, so we copy it.
    std::ranges::copy(input, ret.begin());

    [[maybe_unused]] auto ret_view = std::span(ret);

    (
        [&] {
            if constexpr (HasApply<Ts>) {
                current_size = Ts::expand(current_size);
                Ts::apply(ret_view.first(current_size));
            }
        }(),
        ...
    );

    return ret;
}

template <std::size_t FnSize, IsNfcTransmitDataTransformer... Ts>
constexpr auto transform_nfc_transmit_data_parity(
    std::span<const std::uint8_t, FnSize> input
) {
    std::array<std::uint8_t, FnSize> ret;

    // The input data is actual data (not a parity), so we copy it.
    std::ranges::copy(input, ret.begin());

    (
        [&] {
            if constexpr (HasApplyParity<Ts>) {
                Ts::apply_parity(std::span(ret));
            }
        }(),
        ...
    );

    return ret;
}

template <typename... Args>
struct SelectParityCalculatorTransformer {
    using type = void;
};

template <HasParityCalculator First, typename... Rest>
struct SelectParityCalculatorTransformer<First, Rest...> {
    using type = First;
};

template <typename T>
constexpr auto is_static_extent_bytes() {
    using U = std::remove_cvref_t<T>;
    return IsByte<U> || IsStaticExtentStdSpanBytes<U> || IsStdArrayBytes<U>
        || IsCStyleArrayBytes<U>;
}

template <typename T>
constexpr auto get_static_extent_bytes_size() {
    using U = std::remove_cvref_t<T>;
    if constexpr (IsByte<U>) {
        return 1;
    } else if constexpr (IsStaticExtentStdSpanBytes<U>) {
        return U::extent;
    } else if constexpr (IsStdArrayBytes<U>) {
        return std::tuple_size_v<U>;
    } else if constexpr (IsCStyleArrayBytes<U>) {
        return std::extent_v<U>;
    } else {
        static_assert(false, "Unsupported type!");
    }
}

template <typename T>
constexpr auto get_dynamic_extent_bytes_size(T&& t) {
    using U = std::remove_cvref_t<decltype(t)>;
    if constexpr (std::convertible_to<U, std::uint8_t>) {
        return 1;
    } else {
        return std::ranges::size(t);
    }
}

} // namespace detail

namespace mifare {

#if NFCPP_ENABLE_CRAPTO1
class MifareCrypto1Cipher {
public:
    explicit MifareCrypto1Cipher(std::uint64_t key = 0) {
        crypto1_init(&m_state, key);
    };

    // bare c methods
    // - prng_successor
    // - nonce_distance
    // - validate_prng_nonce

    // unused
    // - lfsr_common_prefix
    // - lfsr_prefix_ks

    void init(std::uint64_t key) { crypto1_init(&m_state, key); }

    auto get_lfsr() const {
        std::uint64_t ret{};
        crypto1_get_lfsr(
            &const_cast<MifareCrypto1Cipher&>(*this).m_state,
            &ret
        );
        return ret;
    }

    auto bit(std::uint8_t input, bool is_encrypted) {
        return crypto1_bit(&m_state, input, is_encrypted);
    }
    auto byte(std::uint8_t input, bool is_encrypted) {
        return crypto1_byte(&m_state, input, is_encrypted);
    }
    auto word(std::uint32_t input, bool is_encrypted) {
        return crypto1_word(&m_state, input, is_encrypted);
    }

    auto rollback_bit(std::uint32_t input, bool feedback) {
        return lfsr_rollback_bit(&m_state, input, feedback);
    }
    auto rollback_byte(std::uint32_t input, bool feedback) {
        return lfsr_rollback_byte(&m_state, input, feedback);
    }
    auto rollback_word(std::uint32_t input, bool feedback) {
        return lfsr_rollback_word(&m_state, input, feedback);
    }

    auto filter() { return ::filter(m_state.odd); }

    auto get(this auto& self) { return &self.m_state; };

    auto odd() const { return m_state.odd; }

    auto even() const { return m_state.even; }

    bool operator==(const MifareCrypto1Cipher& other) const {
        return m_state.odd == other.m_state.odd
            && m_state.even == other.m_state.even;
    }

    class StateList {
    public:
        auto operator*(this auto& self) { return self.m_view; }

    private:
        friend class MifareCrypto1Cipher;
        explicit StateList(Crypto1State* head) : m_ownership(head) {
            std::size_t size{};
            for (auto ptr = head; ptr->even | ptr->odd; ptr++) size++;
            m_view =
                std::span(reinterpret_cast<MifareCrypto1Cipher*>(head), size);
        }

        std::unique_ptr<Crypto1State>  m_ownership;
        std::span<MifareCrypto1Cipher> m_view;
    };

    static auto recovery32(std::uint32_t keystream, std::uint32_t input) {
        auto ptr = lfsr_recovery32(keystream, input);
        return StateList(ptr);
    }

    static auto
    recovery64(std::uint32_t keystream_h32, std::uint32_t keystream_l32) {
        auto ptr = lfsr_recovery64(keystream_h32, keystream_l32);
        return StateList(ptr);
    }

private:
    Crypto1State m_state;
};

static_assert(
    std::is_standard_layout_v<MifareCrypto1Cipher>
    && sizeof(MifareCrypto1Cipher) == sizeof(Crypto1State)
);

#endif

} // namespace mifare

namespace util {

template <std::integral T>
constexpr T to_big_endian(T value) {
    if constexpr (std::endian::native == std::endian::little)
        return std::byteswap(value);
    else return value;
}

template <std::ranges::contiguous_range T>
constexpr std::string hex(const T& data) {
    auto bytes = std::as_bytes(std::span{data});

    if (bytes.empty()) {
        return {};
    }

    std::string ret;
    ret.reserve(bytes.size() * 3 - 1);

    for (auto byte : bytes) {
        std::format_to(
            std::back_inserter(ret),
            "{:02X} ",
            static_cast<std::uint8_t>(byte)
        );
    }
    ret.pop_back();

    return ret;
}

template <typename T>
    requires(detail::TriviallyCopyable<T> && !std::ranges::range<T>)
constexpr std::string hex(const T& object) {
    return hex(std::span<const T, 1>(&object, 1));
}

template <detail::IsByte... Bytes>
constexpr bool is_bytes(std::span<const std::uint8_t> span, Bytes... bytes) {
    const auto     data_size    = span.size();
    constexpr auto pattern_size = sizeof...(Bytes);

    if (data_size != pattern_size) return false;
    const std::array<std::uint8_t, pattern_size> pattern{
        static_cast<std::uint8_t>(bytes)...
    };

    return std::ranges::equal(span, pattern);
}

template <std::ranges::contiguous_range T>
constexpr auto bcc(const T& range) {
    return std::ranges::fold_left(range, std::uint8_t{0}, std::bit_xor<>());
}

template <detail::IsByteOrByteRange... Bytes>
constexpr auto concat_bytes(Bytes... bytes) {
    if constexpr ((detail::is_static_extent_bytes<Bytes>() && ...)) {
        constexpr auto size =
            (detail::get_static_extent_bytes_size<Bytes>() + ...);
        std::array<uint8_t, size> ret;

        auto it = ret.begin();

        auto append = [&](auto&& byte) {
            using T = std::remove_cvref_t<decltype(byte)>;
            if constexpr (std::convertible_to<T, std::uint8_t>) {
                *it++ = static_cast<std::uint8_t>(byte);
            } else {
                it = std::ranges::copy(byte, it).out;
            }
        };

        (append(std::forward<Bytes>(bytes)), ...);
        return ret;
    } else {
        std::vector<uint8_t> ret;

        auto size = (detail::get_dynamic_extent_bytes_size(bytes) + ...);
        ret.reserve(size);

        auto append = [&](auto&& byte) {
            using T = std::remove_cvref_t<decltype(byte)>;
            if constexpr (std::convertible_to<T, std::uint8_t>) {
                ret.emplace_back(static_cast<std::uint8_t>(byte));
            } else {
                ret.insert_range(ret.end(), byte);
            }
        };

        (append(std::forward<Bytes>(bytes)), ...);
        return ret;
    }
}

} // namespace util

class Nfc {
public:
    static std::string_view get_version() { return nfc_version(); }
};

class NfcException : public std::runtime_error {
public:
    NfcException(NfcError error_code, std::string error_msg)
    : std::runtime_error(error_msg),
      m_error_code(error_code) {}

    auto error_code() const { return m_error_code; }

private:
    NfcError m_error_code{};
};

class NfcParityCalculator {
public:
    template <std::size_t In>
    static constexpr void operator()(std::span<std::uint8_t, In> input) {
        for (auto i : std::views::iota(0uz, In)) {
            input[i] = oddparity(input[i]);
        }
    }

private:
    static constexpr std::uint8_t oddparity(const std::uint8_t byte) {
        // https://graphics.stanford.edu/~seander/bithacks.html#ParityParallel
        return (0x9669 >> ((byte ^ (byte >> 4)) & 0xF)) & 1;
    }
};

template <NfcCRC CrcType>
struct NfcTransmitDataCRCTransformer {
    static constexpr std::size_t expand(std::size_t in) { return in + 2; }

    static constexpr void apply(std::span<std::uint8_t> input) {
        const auto data_start = const_cast<std::uint8_t*>(input.data());
        const auto data_size  = input.size() - 2;
        const auto crc_start  = input.data() + data_size;

        if constexpr (CrcType == NfcCRC::ISO14443A) {
            iso14443a_crc(data_start, data_size, crc_start);
        }
        if constexpr (CrcType == NfcCRC::ISO14443B) {
            iso14443b_crc(data_start, data_size, crc_start);
        }
    }
};

struct NfcTransmitDataBCCTransformer {
    static constexpr std::size_t expand(std::size_t in) { return in + 1; }

    static constexpr void apply(std::span<std::uint8_t> input) {
        const auto size = input.size();
        input[size - 1] = util::bcc(input.first(size - 1));
    }
};

// This is actually a `Transformer`, but due to its special status: when
// automatic parity is enabled, it must be placed first in the Ts... parameter
// package, and to avoid confusion, it is renamed to `Calculator`.
template <detail::IsParityCalculator ParityCalc>
struct NfcTransmitDataParityCalculator {
    template <std::size_t In>
    static constexpr void apply_parity(std::span<std::uint8_t, In> input) {
        parity_calculator()(input);
    }

    // Required by concept `HasParityCalculator`.
    using parity_calculator = ParityCalc;
};

class NfcISO14443ATargetInfo {
public:
    explicit NfcISO14443ATargetInfo(const nfc_target_info* ptr)
    : m_info(&ptr->nai) {}

    auto atqa() const {
        return std::array<std::uint8_t, 2>{
            m_info->abtAtqa[0],
            m_info->abtAtqa[1]
        };
    }

    auto atqa_view() const {
        return std::span<const std::uint8_t, 2>(m_info->abtAtqa);
    }

    auto sak() const { return m_info->btSak; }

    auto uid() const {
        return std::vector<std::uint8_t>(
            m_info->abtUid,
            m_info->abtUid + m_info->szUidLen
        );
    }

    auto uid_view() const {
        return std::span<const std::uint8_t>{m_info->abtUid, m_info->szUidLen};
    }

    auto nuid() const {
        auto          id = uid_view();
        std::uint32_t ret;

        std::memcpy(&ret, id.data(), sizeof(ret));

        return util::to_big_endian(ret);
    }

    auto ats_view() const {
        return std::span<const std::uint8_t>{m_info->abtAts, m_info->szAtsLen};
    }

private:
    const nfc_iso14443a_info* m_info;
};

class NfcTarget {
public:
    NfcTarget() = default;

    enum SupportedTarget {
        ISO14443A,
    };

    auto& get(this auto& self) { return self.m_target; }

    auto get_modulation_type() const { return m_target.nm.nmt; }

    auto get_baud_rate() const { return m_target.nm.nbr; }

    template <detail::IsNfcTargetInfo T>
    auto get_info() const {
        return std::make_unique<T>(&m_target.nti);
    }

private:
    nfc_target m_target;
};

template <std::size_t Base, detail::IsNfcTransmitDataTransformer... Ts>
class NfcTransmitData {
public:
    static constexpr std::size_t buffer_size =
        detail::compute_nfc_transmit_data_size<Base, Ts...>();
    static constexpr auto parity_enabled = !std::is_same_v<
        typename detail::SelectParityCalculatorTransformer<Ts...>::type,
        void>;
#if NFCPP_ENABLE_CRAPTO1
    using cipher_t = mifare::MifareCrypto1Cipher;
#endif
    constexpr explicit NfcTransmitData(
        const std::array<std::uint8_t, Base>& raw
    )
    : m_buffer(
          detail::transform_nfc_transmit_data<Base, buffer_size, Ts...>(raw)
      ),
      m_parity_buffer(
          // The first transformer's `apply_parity` converts `m_buffer` into
          // parity bytes.
          detail::transform_nfc_transmit_data_parity<buffer_size, Ts...>(
              m_buffer
          )
      ) {}

    template <detail::IsByteOrByteRange... Bytes>
    // Although util::concat_bytes supports dynamic arrays, we still require the
    // transmit data size to be determined at compile time.
        requires(
            (detail::is_static_extent_bytes<Bytes>() && ...)
            && (detail::get_static_extent_bytes_size<Bytes>() + ...) == Base
        )
    constexpr explicit NfcTransmitData(Bytes... bytes)
    : NfcTransmitData(util::concat_bytes(bytes...)) {}

    constexpr auto get(this auto& self) { return std::span(self.m_buffer); }

    constexpr auto get_parity(this auto& self)
        requires parity_enabled
    {
        return self.m_parity_buffer.get();
    }
#if NFCPP_ENABLE_CRAPTO1
    class CryptWrapper {
    public:
        void crypt_feed(std::size_t len) { _crypt(len, true); }
        void crypt(std::size_t len) { _crypt(len, false); };

    private:
        friend class NfcTransmitData<Base, Ts...>;

        using parent_t = NfcTransmitData<Base, Ts...>;

        CryptWrapper(cipher_t& cipher, parent_t& parent)
        : m_cipher(cipher),
          m_parent(parent) {}

        void _crypt(std::size_t len, bool feedback) {
            for (auto _ : std::views::iota(m_offset, m_offset + len)) {
                if (m_offset >= parent_t::buffer_size) {
                    // TODO: Better handle this situation.
                    // TODO: I hope to perform this check during compilation.
                    return std::println(
                        "!!! warning: encryption request overflowed buffer."
                    );
                }
                auto& byte = m_parent.m_buffer[m_offset];
                byte = m_cipher.byte(feedback ? byte : 0x00, false) ^ byte;
                if constexpr (parent_t::parity_enabled) {
                    auto& parity = m_parent.m_parity_buffer.get()[m_offset];
                    parity       = m_cipher.filter() ^ parity;
                }
                m_offset++;
            }
        }

        cipher_t&   m_cipher;
        parent_t&   m_parent;
        std::size_t m_offset{};
    };

    template <typename F>
        requires std::invocable<F, CryptWrapper&&>
    auto with_encrypt(cipher_t& cipher, F&& callback) {
        callback(CryptWrapper(cipher, *this));
        return *this;
    }
#endif
private:
    std::array<std::uint8_t, buffer_size> m_buffer{};
    [[no_unique_address]] detail::ParityStorage<parity_enabled, buffer_size>
        m_parity_buffer;
};

template <
    detail::IsByteOrByteRange... Bytes,
    detail::IsNfcTransmitDataTransformer... Ts>
NfcTransmitData(Bytes...) -> NfcTransmitData<
    (detail::get_static_extent_bytes_size<Bytes>() + ...),
    Ts...>;

template <std::size_t N, detail::IsNfcTransmitDataTransformer... Ts>
NfcTransmitData(const std::array<std::uint8_t, N>&)
    -> NfcTransmitData<N, Ts...>;

// TODO: Can we delete permutations and combinations?
// BEGIN vvv

template <std::size_t N, NfcCRC C>
using NfcTransmitDataAutoCRC =
    NfcTransmitData<N, NfcTransmitDataCRCTransformer<C>>;

template <std::size_t N, detail::IsParityCalculator P = NfcParityCalculator>
using NfcTransmitDataAutoParity =
    NfcTransmitData<N, NfcTransmitDataParityCalculator<P>>;

template <
    std::size_t                N,
    NfcCRC                     C,
    detail::IsParityCalculator P = NfcParityCalculator>
using NfcTransmitDataAutoCRCParity = NfcTransmitData<
    N,
    NfcTransmitDataParityCalculator<P>,
    NfcTransmitDataCRCTransformer<C>>;

// END   ^^^

class NfcDevice {
public:
    class Initiator {
    public:
        // TODO:
        // - nfc_initiator_list_passive_targets
        // - nfc_initiator_poll_target
        // - nfc_initiator_select_dep_target
        // - nfc_initiator_poll_dep_target
        // - nfc_initiator_transceive_bytes_timed
        // - nfc_initiator_transceive_bits_timed
        // - nfc_initiator_target_is_present

        auto select_passive_target(
            nfc_modulation_type           modulation_type,
            nfc_baud_rate                 baud_rate,
            std::span<const std::uint8_t> uid = {}
        ) {
            NfcTarget target;
            auto      modulation = nfc_modulation{modulation_type, baud_rate};

            auto ret = nfc_initiator_select_passive_target(
                m_device,
                modulation,
                uid.empty() ? nullptr : uid.data(),
                uid.empty() ? 0 : uid.size(),
                &target.get()
            );
            NFCPP_LIBNFC_ENSURE(ret);

            return target;
        }

        auto select_passive_target(
            NfcCard                       card,
            std::span<const std::uint8_t> uid = {}
        ) {
            auto [type, baud_rate] = get_modulation_from_card(card);
            return select_passive_target(type, baud_rate, uid);
        }

        void deselect_target() {
            NFCPP_LIBNFC_ENSURE(nfc_initiator_deselect_target(m_device));
        }

        template <bool BitMode>
        class ResultWrapper {
        public:
            template <detail::IsByte... Bytes>
            bool is_bytes(Bytes... bytes) const {
                return util::is_bytes(
                    m_buffer_view.first(size_in_byte()),
                    bytes...
                );
            }

            bool check_bcc() const {
                return util::bcc(m_buffer_view.first(size_in_byte())) == 0;
            }

            template <NfcCRC CRCType>
            bool check_crc() const {
                std::array<std::uint8_t, 2> crc;

                if (size_in_byte() < 3) {
                    throw NfcException(
                        NfcError::INVARG,
                        "check_crc was called, but the data was less than 3 "
                        "bytes."
                    );
                }

                if constexpr (CRCType == NfcCRC::ISO14443A) {
                    iso14443a_crc(
                        m_buffer_view.data(),
                        size_in_byte() - 2,
                        crc.data()
                    );
                }

                if constexpr (CRCType == NfcCRC::ISO14443B) {
                    iso14443b_crc(
                        m_buffer_view.data(),
                        size_in_byte() - 2,
                        crc.data()
                    );
                }

                return std::ranges::equal(
                    m_buffer_view.first(size_in_byte()).last(2),
                    crc
                );
            }

            auto& as_big_endian() {
                if constexpr (std::endian::native == std::endian::little)
                    std::ranges::reverse(
                        m_buffer_view | std::views::take(size_in_byte())
                    );
                return *this;
            }
#if NFCPP_ENABLE_CRAPTO1
            auto& as_decrypted(
                mifare::MifareCrypto1Cipher& cipher,
                bool                         feedback,
                bool                         is_encrypted
            ) {
                auto valid_size = size_in_byte();
                if constexpr (BitMode) {
                    auto diff = m_valid_size - aligndn_8(m_valid_size);
                    if (diff > 0) valid_size -= 1;
                    auto& byte = m_buffer_view[valid_size]; // Last byte.
                    for (auto i : std::views::iota(0uz, diff)) {
                        byte |= cipher.bit(BIT(byte, i), is_encrypted) << i;
                    }
                }
                for (auto i :
                     std::views::iota(0uz, valid_size) | std::views::reverse) {
                    auto& byte = m_buffer_view[i];
                    byte = cipher.byte(feedback ? byte : 0x00, is_encrypted)
                         ^ byte;
                }
                return *this;
            }
#endif

            template <detail::TriviallyCopyable T>
            auto& get() const {
                return *reinterpret_cast<const T*>(m_buffer_view.data());
            }

            template <std::size_t Idx>
            auto get_byte() const {
                return m_buffer_view[Idx];
            }

            template <std::size_t Sz>
            auto get_bytes() const {
                std::array<std::uint8_t, Sz> ret;
                std::ranges::copy_n(m_buffer_view.begin(), Sz, ret.begin());
                return ret;
            }

            template <std::size_t Sz>
            auto get_bytes_view() const {
                return m_buffer_view.template first<Sz>();
            }

            template <detail::TriviallyCopyable T>
            auto& expect() const {
                constexpr std::size_t expect_size =
                    BitMode ? sizeof(T) * 8 : sizeof(T);
                _throw_if_size_mismatch<expect_size>();
                return get<T>();
            }

            template <std::size_t Idx>
            auto expect_byte() const {
                constexpr std::size_t expect_size =
                    BitMode ? (Idx + 1) * 8 : (Idx + 1);
                _throw_if_size_mismatch<expect_size>();
                return get_bytes<Idx>();
            }

            template <std::size_t Sz>
            auto expect_bytes() const {
                constexpr std::size_t expect_size = BitMode ? Sz * 8 : Sz;
                _throw_if_size_mismatch<expect_size>();
                return get_bytes<Sz>();
            }

            template <std::size_t Sz>
            auto expect_bytes_view() const {
                constexpr std::size_t expect_size = BitMode ? Sz * 8 : Sz;
                _throw_if_size_mismatch<expect_size>();
                return get_bytes_view<Sz>();
            }

            template <std::size_t SzInBit>
            auto expect_bits() const
                requires BitMode
            {
                _throw_if_size_mismatch<SzInBit>();
                return get_bytes<alignup_8(SzInBit) / 8>();
            }

            template <std::size_t SzInBit>
            auto expect_bits_view() const
                requires BitMode
            {
                _throw_if_size_mismatch<SzInBit>();
                return get_bytes_view<alignup_8(SzInBit) / 8>();
            }

            auto empty() const { return m_valid_size == 0; }

            auto size() const { return m_valid_size; }

            auto size_in_byte() const {
                return BitMode ? alignup_8(m_valid_size) / 8 : m_valid_size;
            }

        private:
            friend class Initiator;
            ResultWrapper(
                std::span<std::uint8_t> buffer_view,
                std::size_t             valid_size
            )
            : m_buffer_view(buffer_view),
              m_valid_size(valid_size) {}

            template <std::size_t SizeMayInBits>
            void _throw_if_size_mismatch() const {
                if (m_valid_size != SizeMayInBits) {
                    throw NfcException(
                        NfcError::INVARG,
                        std::format(
                            "transceive_{0} received {1} but expect {2} {0}.",
                            BitMode ? "bits" : "bytes",
                            m_valid_size,
                            SizeMayInBits
                        )
                    );
                }
            }

            static constexpr std::size_t alignup_8(std::size_t x) {
                return (x + 7) & ~7;
            }

            static constexpr std::size_t aligndn_8(std::size_t x) {
                return x & ~7;
            }

            std::span<std::uint8_t> m_buffer_view;
            std::size_t             m_valid_size; // Possibly in bits.
        };

        auto transceive_bytes(
            const detail::HasReadableByteSpan auto& tx_data,
            detail::HasMutableByteSpan auto&        rx_data,
            int                                     timeout = 0
        ) {
            auto tx = tx_data.get();
            auto rx = rx_data.get();

            auto ret = nfc_initiator_transceive_bytes(
                m_device,
                tx.data(),
                tx.size(),
                rx.data(),
                rx.size(),
                timeout
            );
            NFCPP_LIBNFC_ENSURE(ret);

            return ResultWrapper<false>(rx, ret);
        }

        // Ensure NP_HANDLE_PARITY == true if AutoParity is not used,
        // otherwise, libnfc will access to null pointer!
        template <detail::HasReadableByteSpan Tx, detail::HasMutableByteSpan Rx>
        auto transceive_bits(
            const Tx&               tx_data,
            Rx&                     rx_data,
            std::size_t             tx_size_in_bit = 0,
            detail::OptionalRef<Rx> rx_data_par    = std::nullopt
        ) {
            using tx_data_t = std::remove_cvref_t<decltype(tx_data)>;

            auto tx      = tx_data.get();
            auto rx      = rx_data.get();
            auto tx_size = tx_size_in_bit != 0 ? tx_size_in_bit : tx.size() * 8;

            int ret{};

            if constexpr (detail::HasParityGetter<tx_data_t>) {
                auto parity = tx_data.get_parity();
                auto rx_par =
                    rx_data_par ? rx_data_par->get().get().data() : nullptr;

                ret = nfc_initiator_transceive_bits(
                    m_device,
                    tx.data(),
                    tx_size,
                    parity.data(),
                    rx.data(),
                    rx.size(),
                    rx_par
                );
            } else {
                ret = nfc_initiator_transceive_bits(
                    m_device,
                    tx.data(),
                    tx_size,
                    nullptr,
                    rx.data(),
                    rx.size(),
                    nullptr
                );
            }
            NFCPP_LIBNFC_ENSURE(ret);

            return ResultWrapper<true>(rx, ret);
        }

    private:
        friend class NfcDevice;
        nfc_device* m_device{};

        explicit Initiator(NfcDevice& parent) : m_device(&*parent.m_device) {
            NFCPP_LIBNFC_ENSURE(nfc_initiator_init(m_device));
        }

        static nfc_modulation get_modulation_from_card(NfcCard card) {
            switch (card) {
            case NfcCard::Mifare:
                return {.nmt = NMT_ISO14443A, .nbr = NBR_106};
            default:
                throw NfcException(NfcError::INVARG, "Unreachable.");
            }
        }
    };

    class Target {
    public:
        // TODO:
        // - nfc_target_send_bytes
        // - nfc_target_receive_bytes
        // - nfc_target_send_bits
        // - nfc_target_receive_bits

    private:
        friend class NfcDevice;
        nfc_device* m_device{};

        Target(NfcDevice& parent, NfcTarget& target, int timeout)
        : m_device(&*parent.m_device) {
            NFCPP_LIBNFC_ENSURE(
                nfc_target_init(m_device, &target.get(), nullptr, 0, timeout)
            );
        }
    };

    void set_property(nfc_property property, bool enable) {
        NFCPP_LIBNFC_ENSURE(
            nfc_device_set_property_bool(&*m_device, property, enable)
        );
    }

    void set_property(nfc_property property, int value) {
        NFCPP_LIBNFC_ENSURE(
            nfc_device_set_property_int(&*m_device, property, value)
        );
    }

    std::string_view get_name() const {
        return nfc_device_get_name(&*m_device);
    }

    std::string_view get_connstring() const {
        return nfc_device_get_connstring(&*m_device);
    }

    void abort() { nfc_abort_command(&*m_device); }

    void idle() { nfc_idle(&*m_device); }

    // TODO:
    // - nfc_device_get_supported_modulation
    // - nfc_device_get_supported_baud_rate
    // - nfc_device_get_supported_baud_rate_target_mode

    auto get(this auto& self) { return &*self.m_device; }

    auto as_initiator() {
        return std::unique_ptr<Initiator>(new Initiator(*this));
    }
    auto as_target(NfcTarget& target, int timeout) {
        return std::unique_ptr<Target>(new Target(*this, target, timeout));
    }

    template <typename Driver>
    auto get_driver() {
        return std::unique_ptr<Driver>(new Driver(*this));
    }

private:
    friend class NfcContext;
    friend class NfcPN53xDriver;
    NfcDevice(nfc_device* device) : m_device(device, nfc_close) {}

    std::unique_ptr<nfc_device, detail::Ptr<void(nfc_device*)>> m_device;
};

class NfcPN53xDriver {
public:
    void write_register(
        std::uint16_t reg,
        std::uint8_t  symbol_mask,
        std::uint8_t  value
    ) {
        pn53x_write_register(m_device, reg, symbol_mask, value);
    }

private:
    friend class NfcDevice;
    nfc_device* m_device{};

    explicit NfcPN53xDriver(NfcDevice& parent) : m_device(&*parent.m_device) {}
};

class NfcPN53xFrameBuffer {
public:
    auto get(this auto& self) { return std::span(self.m_buffer); }

private:
    // T m_object;
    //
    // nfc_initiator_transceive_bits will directly ignore szRx, and in order
    // to avoid out-of-bounds writes, memory can only be allocated according
    // to the frame size.
    std::array<std::uint8_t, PN53x_EXTENDED_FRAME__DATA_MAX_LEN> m_buffer{};
};

class NfcContext {
public:
    NfcContext() : m_context(nullptr, nfc_exit) {
        nfc_context* ptr{};
        nfc_init(&ptr);
        if (!ptr) {
            throw NfcException(
                NfcError::INVARG,
                "Failed to initialize nfc context!"
            );
        }
        m_context.reset(ptr);
    }

    auto open_device(const std::string& connstring = "") {
        auto device = nfc_open(
            &*m_context,
            connstring.empty() ? nullptr : connstring.c_str()
        );
        return std::unique_ptr<NfcDevice>(
            device ? new NfcDevice(device) : nullptr
        );
    };

    auto list_devices() const {
        constexpr std::size_t MAX_DEVICE_COUNT = 16;

        std::vector<std::string> ret;

        nfc_connstring connstrings[MAX_DEVICE_COUNT];
        auto           count =
            nfc_list_devices(&*m_context, connstrings, MAX_DEVICE_COUNT);

        ret.reserve(count);
        for (auto i : std::views::iota(0uz, count)) {
            ret.emplace_back(connstrings[i]);
        }

        return ret;
    }

private:
    std::unique_ptr<nfc_context, detail::Ptr<void(nfc_context*)>> m_context;
};

} // namespace nfcpp

#undef NFCPP_LIBNFC_ENSURE

#pragma once

#include <cstdint>
#include <limits>
#include <vector>

#include "lz4.h"

namespace protocol {

inline bool CompressRle0(const uint8_t* data, size_t size, std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  if (!data || size == 0) {
    return true;
  }
  size_t i = 0;
  while (i < size) {
    if (data[i] == 0) {
      size_t run = 1;
      while (i + run < size && data[i + run] == 0 && run < 128) {
        ++run;
      }
      out->push_back(static_cast<uint8_t>(0x7F + run));
      i += run;
    } else {
      size_t run = 1;
      while (i + run < size && data[i + run] != 0 && run < 128) {
        ++run;
      }
      out->push_back(static_cast<uint8_t>(run - 1));
      out->insert(out->end(), data + i, data + i + run);
      i += run;
    }
  }
  return true;
}

inline bool CompressLz4(const uint8_t* data, size_t size, std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  if (!data || size == 0) {
    return true;
  }
  if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  const int input_size = static_cast<int>(size);
  const int bound = LZ4_compressBound(input_size);
  if (bound <= 0) {
    return false;
  }
  out->resize(static_cast<size_t>(bound));
  const int written = LZ4_compress_default(reinterpret_cast<const char*>(data),
                                           reinterpret_cast<char*>(out->data()),
                                           input_size,
                                           bound);
  if (written <= 0) {
    out->clear();
    return false;
  }
  out->resize(static_cast<size_t>(written));
  return true;
}

inline bool DecompressRle0(const uint8_t* data,
                           size_t size,
                           size_t raw_size,
                           std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  out->reserve(raw_size);
  if (!data || size == 0) {
    return raw_size == 0;
  }
  size_t i = 0;
  while (i < size && out->size() < raw_size) {
    const uint8_t ctrl = data[i++];
    if (ctrl <= 0x7F) {
      const size_t len = static_cast<size_t>(ctrl) + 1;
      if (i + len > size || out->size() + len > raw_size) {
        return false;
      }
      out->insert(out->end(), data + i, data + i + len);
      i += len;
    } else {
      const size_t len = static_cast<size_t>(ctrl - 0x7F);
      if (out->size() + len > raw_size) {
        return false;
      }
      out->insert(out->end(), len, 0);
    }
  }
  return out->size() == raw_size;
}

inline bool DecompressLz4(const uint8_t* data,
                          size_t size,
                          size_t raw_size,
                          std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  out->clear();
  if (!data || size == 0) {
    return raw_size == 0;
  }
  if (raw_size > static_cast<size_t>(std::numeric_limits<int>::max()) ||
      size > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  out->resize(raw_size);
  const int decoded = LZ4_decompress_safe(reinterpret_cast<const char*>(data),
                                          reinterpret_cast<char*>(out->data()),
                                          static_cast<int>(size),
                                          static_cast<int>(raw_size));
  if (decoded < 0 || static_cast<size_t>(decoded) != raw_size) {
    return false;
  }
  return true;
}

inline bool CompressPayloadIfUseful(const uint8_t* data,
                                    size_t size,
                                    std::vector<uint8_t>* out,
                                    CompressionType* algo,
                                    size_t min_size = 1024,
                                    size_t min_savings = 64) {
  if (!out || !algo) {
    return false;
  }
  *algo = COMPRESS_NONE;
  out->clear();
  if (!data || size == 0 || size < min_size) {
    return false;
  }
  std::vector<uint8_t> best;
  CompressionType best_algo = COMPRESS_NONE;

  std::vector<uint8_t> compressed;
  if (CompressLz4(data, size, &compressed)) {
    if (compressed.size() + sizeof(CompressedPayloadHeader) < size &&
        size - compressed.size() >= min_savings) {
      best.swap(compressed);
      best_algo = COMPRESS_LZ4;
    }
  }

  compressed.clear();
  if (CompressRle0(data, size, &compressed)) {
    if (compressed.size() + sizeof(CompressedPayloadHeader) < size &&
        size - compressed.size() >= min_savings) {
      if (best_algo == COMPRESS_NONE || compressed.size() < best.size()) {
        best.swap(compressed);
        best_algo = COMPRESS_RLE0;
      }
    }
  }

  if (best_algo == COMPRESS_NONE) {
    return false;
  }

  *algo = best_algo;
  out->swap(best);
  return true;
}

inline bool DecompressPayload(CompressionType algo,
                              const uint8_t* data,
                              size_t size,
                              size_t raw_size,
                              std::vector<uint8_t>* out) {
  if (!out) {
    return false;
  }
  switch (algo) {
    case COMPRESS_RLE0:
      return DecompressRle0(data, size, raw_size, out);
    case COMPRESS_LZ4:
      return DecompressLz4(data, size, raw_size, out);
    default:
      return false;
  }
}

} // namespace protocol

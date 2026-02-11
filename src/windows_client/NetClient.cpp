#include "NetClient.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

#include "../protocol/Compression.h"

NetClient::NetClient() : sock_(INVALID_SOCKET) {}

NetClient::~NetClient() { Disconnect(); }

bool NetClient::Connect(const char* host, uint16_t port) {
  Disconnect();

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char port_str[16] = {0};
  std::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(port));

  addrinfo* result = nullptr;
  if (getaddrinfo(host, port_str, &hints, &result) != 0) {
    return false;
  }

  SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (s == INVALID_SOCKET) {
    freeaddrinfo(result);
    return false;
  }

  if (connect(s, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR) {
    closesocket(s);
    freeaddrinfo(result);
    return false;
  }

  freeaddrinfo(result);
  sock_ = s;
  rtt_ewma_ms_ = 0.0;
  last_exchange_ = ExchangeStats{};
  return true;
}

void NetClient::Disconnect() {
  if (sock_ != INVALID_SOCKET) {
    closesocket(sock_);
    sock_ = INVALID_SOCKET;
  }
  rtt_ewma_ms_ = 0.0;
  last_exchange_ = ExchangeStats{};
}

bool NetClient::IsConnected() const { return sock_ != INVALID_SOCKET; }

bool NetClient::SendAll(const void* data, size_t size) {
  const char* ptr = static_cast<const char*>(data);
  size_t offset = 0;
  while (offset < size) {
    int sent = send(sock_, ptr + offset, static_cast<int>(size - offset), 0);
    if (sent == SOCKET_ERROR || sent == 0) {
      return false;
    }
    offset += static_cast<size_t>(sent);
  }
  return true;
}

bool NetClient::RecvAll(void* data, size_t size) {
  char* ptr = static_cast<char*>(data);
  size_t offset = 0;
  while (offset < size) {
    int recvd = recv(sock_, ptr + offset, static_cast<int>(size - offset), 0);
    if (recvd == SOCKET_ERROR || recvd == 0) {
      return false;
    }
    offset += static_cast<size_t>(recvd);
  }
  return true;
}

bool NetClient::ShouldAttemptRequestCompression(protocol::CommandType cmd, uint32_t size) const {
  (void)cmd;
  (void)size;
  // Windows-side override: disable request compression globally.
  return false;
}

bool NetClient::SendPacket(protocol::CommandType cmd,
                           const void* payload,
                           uint32_t size,
                           uint32_t* out_wire_bytes,
                           bool* out_used_compression) {
  if (out_wire_bytes) {
    *out_wire_bytes = 0;
  }
  if (out_used_compression) {
    *out_used_compression = false;
  }
  if (!IsConnected()) {
    return false;
  }
  protocol::PacketHeader header{};
  header.magic = protocol::kMagic;
  header.command = static_cast<uint16_t>(cmd);
  header.reserved = 0;
  header.data_size = size;

  std::vector<uint8_t> compressed;
  protocol::CompressionType algo = protocol::COMPRESS_NONE;
  if (size > 0 &&
      ShouldAttemptRequestCompression(cmd, size) &&
      protocol::CompressPayloadIfUseful(static_cast<const uint8_t*>(payload),
                                        size,
                                        &compressed,
                                        &algo)) {
    const size_t comp_header = offsetof(protocol::CompressedPayloadHeader, data);
    const size_t total = comp_header + compressed.size();
    std::vector<uint8_t> out(total);
    auto* comp = reinterpret_cast<protocol::CompressedPayloadHeader*>(out.data());
    comp->raw_size = size;
    comp->algorithm = static_cast<uint16_t>(algo);
    comp->reserved = 0;
    std::memcpy(comp->data, compressed.data(), compressed.size());
    header.reserved = protocol::PACKET_FLAG_COMPRESSED;
    header.data_size = static_cast<uint32_t>(out.size());
    if (!SendAll(&header, sizeof(header))) {
      return false;
    }
    if (!SendAll(out.data(), out.size())) {
      return false;
    }
    if (out_wire_bytes) {
      const size_t wire = sizeof(header) + out.size();
      *out_wire_bytes = wire > std::numeric_limits<uint32_t>::max()
                            ? std::numeric_limits<uint32_t>::max()
                            : static_cast<uint32_t>(wire);
    }
    if (out_used_compression) {
      *out_used_compression = true;
    }
    return true;
  }

  if (!SendAll(&header, sizeof(header))) {
    return false;
  }
  if (size == 0) {
    if (out_wire_bytes) {
      *out_wire_bytes = static_cast<uint32_t>(sizeof(header));
    }
    return true;
  }
  if (!SendAll(payload, size)) {
    return false;
  }
  if (out_wire_bytes) {
    const size_t wire = sizeof(header) + size;
    *out_wire_bytes = wire > std::numeric_limits<uint32_t>::max()
                          ? std::numeric_limits<uint32_t>::max()
                          : static_cast<uint32_t>(wire);
  }
  return true;
}

bool NetClient::ReceivePacket(protocol::PacketHeader* header,
                              std::vector<uint8_t>* payload,
                              uint32_t* out_wire_bytes,
                              bool* out_was_compressed) {
  if (out_wire_bytes) {
    *out_wire_bytes = 0;
  }
  if (out_was_compressed) {
    *out_was_compressed = false;
  }
  if (!header || !payload || !IsConnected()) {
    return false;
  }
  if (!RecvAll(header, sizeof(*header))) {
    return false;
  }
  if (header->magic != protocol::kMagic) {
    return false;
  }
  if (out_wire_bytes) {
    const size_t wire = sizeof(*header) + static_cast<size_t>(header->data_size);
    *out_wire_bytes = wire > std::numeric_limits<uint32_t>::max()
                          ? std::numeric_limits<uint32_t>::max()
                          : static_cast<uint32_t>(wire);
  }
  payload->assign(header->data_size, 0);
  if (header->data_size > 0) {
    if (!RecvAll(payload->data(), payload->size())) {
      return false;
    }
  }
  if ((header->reserved & protocol::PACKET_FLAG_COMPRESSED) != 0) {
    if (out_was_compressed) {
      *out_was_compressed = true;
    }
    if (payload->size() < offsetof(protocol::CompressedPayloadHeader, data)) {
      return false;
    }
    const auto* comp = reinterpret_cast<const protocol::CompressedPayloadHeader*>(payload->data());
    const size_t raw_size = comp->raw_size;
    if (raw_size > 16u * 1024u * 1024u) {
      return false;
    }
    const size_t comp_size = payload->size() - offsetof(protocol::CompressedPayloadHeader, data);
    std::vector<uint8_t> raw;
    if (!protocol::DecompressPayload(static_cast<protocol::CompressionType>(comp->algorithm),
                                     comp->data,
                                     comp_size,
                                     raw_size,
                                     &raw)) {
      return false;
    }
    payload->swap(raw);
  }
  return true;
}

bool NetClient::SendAndReceive(protocol::CommandType cmd,
                               const void* payload,
                               uint32_t size,
                               protocol::PacketHeader* out_header,
                               std::vector<uint8_t>* out_payload) {
  const auto t0 = std::chrono::steady_clock::now();
  uint32_t req_wire_bytes = 0;
  bool req_compressed = false;
  if (!SendPacket(cmd, payload, size, &req_wire_bytes, &req_compressed)) {
    last_exchange_ = ExchangeStats{};
    last_exchange_.request_payload_bytes = size;
    last_exchange_.request_wire_bytes = req_wire_bytes;
    last_exchange_.request_compressed = req_compressed;
    return false;
  }
  uint32_t rsp_wire_bytes = 0;
  bool rsp_compressed = false;
  if (!ReceivePacket(out_header, out_payload, &rsp_wire_bytes, &rsp_compressed)) {
    last_exchange_ = ExchangeStats{};
    last_exchange_.request_payload_bytes = size;
    last_exchange_.request_wire_bytes = req_wire_bytes;
    last_exchange_.request_compressed = req_compressed;
    last_exchange_.response_wire_bytes = rsp_wire_bytes;
    last_exchange_.response_compressed = rsp_compressed;
    return false;
  }

  const auto t1 = std::chrono::steady_clock::now();
  const double elapsed_ms =
      std::chrono::duration<double, std::milli>(t1 - t0).count();
  if (elapsed_ms > 0.0) {
    if (rtt_ewma_ms_ <= 0.0) {
      rtt_ewma_ms_ = elapsed_ms;
    } else {
      rtt_ewma_ms_ = rtt_ewma_ms_ * 0.85 + elapsed_ms * 0.15;
    }
  }

  last_exchange_ = ExchangeStats{};
  last_exchange_.request_payload_bytes = size;
  last_exchange_.request_wire_bytes = req_wire_bytes;
  last_exchange_.request_compressed = req_compressed;
  last_exchange_.response_payload_bytes =
      out_payload->size() > std::numeric_limits<uint32_t>::max()
          ? std::numeric_limits<uint32_t>::max()
          : static_cast<uint32_t>(out_payload->size());
  last_exchange_.response_wire_bytes = rsp_wire_bytes;
  last_exchange_.response_compressed = rsp_compressed;
  last_exchange_.roundtrip_ms = elapsed_ms;
  return true;
}

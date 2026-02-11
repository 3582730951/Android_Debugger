#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "../protocol/Protocol.h"

class NetClient {
 public:
  struct ExchangeStats {
    uint32_t request_payload_bytes = 0;
    uint32_t request_wire_bytes = 0;
    bool request_compressed = false;
    uint32_t response_payload_bytes = 0;
    uint32_t response_wire_bytes = 0;
    bool response_compressed = false;
    double roundtrip_ms = 0.0;
  };

  NetClient();
  ~NetClient();

  bool Connect(const char* host, uint16_t port);
  void Disconnect();
  bool IsConnected() const;

  bool SendPacket(protocol::CommandType cmd,
                  const void* payload,
                  uint32_t size,
                  uint32_t* out_wire_bytes = nullptr,
                  bool* out_used_compression = nullptr);
  bool ReceivePacket(protocol::PacketHeader* header,
                     std::vector<uint8_t>* payload,
                     uint32_t* out_wire_bytes = nullptr,
                     bool* out_was_compressed = nullptr);
  bool SendAndReceive(protocol::CommandType cmd,
                      const void* payload,
                      uint32_t size,
                      protocol::PacketHeader* out_header,
                      std::vector<uint8_t>* out_payload);
  ExchangeStats LastExchangeStats() const { return last_exchange_; }
  double RttEwmaMs() const { return rtt_ewma_ms_; }

 private:
  bool ShouldAttemptRequestCompression(protocol::CommandType cmd, uint32_t size) const;
  bool SendAll(const void* data, size_t size);
  bool RecvAll(void* data, size_t size);

  SOCKET sock_;
  double rtt_ewma_ms_ = 0.0;
  ExchangeStats last_exchange_{};
};

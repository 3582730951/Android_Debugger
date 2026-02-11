#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include "plugin_sdk/R3ModuleCompat.h"
#include "plugins/PluginCatalog.h"
#include "plugins/PluginRuntime.h"
#include "protocol/Protocol.h"
#include "services/ClientService.h"

namespace {

struct Config {
  QString host = QStringLiteral("127.0.0.1");
  uint16_t port = 12345;
  uint32_t pid = 0;
  QString plugin_dll;
  QString out_json;
};

struct StepResult {
  QString name;
  bool passed = false;
  QString detail;
};

std::string ToStdString(const QString& text) {
  const QByteArray utf8 = text.toUtf8();
  return std::string(utf8.constData(), static_cast<size_t>(utf8.size()));
}

QString ToQString(const std::string& text) {
  return QString::fromUtf8(text.c_str(), static_cast<int>(text.size()));
}

void AddResult(std::vector<StepResult>* results, const QString& name, bool passed, const QString& detail) {
  if (!results) {
    return;
  }
  results->push_back(StepResult{name, passed, detail});
  std::cout << (passed ? "[PASS] " : "[FAIL] ") << ToStdString(name) << " - "
            << ToStdString(detail) << "\n";
}

bool ParseArgs(int argc, char** argv, Config* out_cfg, QString* out_error) {
  if (!out_cfg) {
    if (out_error) {
      *out_error = QStringLiteral("config pointer is null");
    }
    return false;
  }
  Config cfg = *out_cfg;
  for (int i = 1; i < argc; ++i) {
    const QString arg = QString::fromLocal8Bit(argv[i]);
    auto need_value = [&](const QString& key, QString* out) -> bool {
      if (i + 1 >= argc) {
        if (out_error) {
          *out_error = QStringLiteral("%1 missing value").arg(key);
        }
        return false;
      }
      *out = QString::fromLocal8Bit(argv[++i]);
      return true;
    };
    if (arg == QStringLiteral("--host")) {
      if (!need_value(arg, &cfg.host)) {
        return false;
      }
      continue;
    }
    if (arg == QStringLiteral("--port")) {
      QString value;
      if (!need_value(arg, &value)) {
        return false;
      }
      bool ok = false;
      const int port = value.toInt(&ok);
      if (!ok || port <= 0 || port > 65535) {
        if (out_error) {
          *out_error = QStringLiteral("invalid --port: %1").arg(value);
        }
        return false;
      }
      cfg.port = static_cast<uint16_t>(port);
      continue;
    }
    if (arg == QStringLiteral("--pid")) {
      QString value;
      if (!need_value(arg, &value)) {
        return false;
      }
      bool ok = false;
      const uint32_t pid = value.toUInt(&ok);
      if (!ok || pid == 0u) {
        if (out_error) {
          *out_error = QStringLiteral("invalid --pid: %1").arg(value);
        }
        return false;
      }
      cfg.pid = pid;
      continue;
    }
    if (arg == QStringLiteral("--plugin-dll")) {
      if (!need_value(arg, &cfg.plugin_dll)) {
        return false;
      }
      continue;
    }
    if (arg == QStringLiteral("--out")) {
      if (!need_value(arg, &cfg.out_json)) {
        return false;
      }
      continue;
    }
    if (arg == QStringLiteral("--help") || arg == QStringLiteral("-h")) {
      if (out_error) {
        *out_error = QStringLiteral(
            "Usage: --plugin-dll <path> --pid <pid> [--host <ip>] [--port <n>] [--out <json>]");
      }
      return false;
    }
    if (out_error) {
      *out_error = QStringLiteral("unknown arg: %1").arg(arg);
    }
    return false;
  }
  if (cfg.plugin_dll.trimmed().isEmpty()) {
    if (out_error) {
      *out_error = QStringLiteral("--plugin-dll is required");
    }
    return false;
  }
  if (cfg.pid == 0u) {
    if (out_error) {
      *out_error = QStringLiteral("--pid is required");
    }
    return false;
  }
  *out_cfg = cfg;
  return true;
}

bool ContainsText(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) {
    return true;
  }
  return haystack.find(needle) != std::string::npos;
}

void SetPluginMode(const char* read_mode, const char* write_mode, const char* fill_hex = "0xAB") {
  _putenv_s("R3_E2E_READ_MODE", read_mode ? read_mode : "handled");
  _putenv_s("R3_E2E_WRITE_MODE", write_mode ? write_mode : "handled");
  _putenv_s("R3_E2E_READ_FILL", fill_hex ? fill_hex : "0xAB");
}

void ConfigureOverrideHooks(r3::windows_client_ng::services::ClientService* service,
                            r3::windows_client_qt::plugins::PluginRuntime* runtime,
                            uint32_t timeout_ms,
                            const std::vector<uint8_t>& user_ctx) {
  using r3::windows_client_ng::services::ClientService;
  ClientService::ReadOverrideHook read_hook =
      [runtime, timeout_ms, user_ctx](uint32_t pid,
                                      uint64_t address,
                                      uint32_t size,
                                      bool use_pvm,
                                      std::vector<uint8_t>* out_data,
                                      std::string* out_error) {
        QString message;
        std::vector<uint8_t> data;
        const int rc = runtime->DispatchReadMemoryEvent(
            pid, address, size, timeout_ms, use_pvm, user_ctx, &data, &message);
        if (rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED)) {
          if (out_data) {
            *out_data = std::move(data);
          }
          return ClientService::OverrideAction::kHandled;
        }
        if (rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR)) {
          if (out_error) {
            *out_error = ToStdString(message.trimmed().isEmpty() ? QStringLiteral("plugin read error")
                                                                 : message.trimmed());
          }
          return ClientService::OverrideAction::kError;
        }
        return ClientService::OverrideAction::kPass;
      };
  ClientService::WriteOverrideHook write_hook =
      [runtime, timeout_ms, user_ctx](uint32_t pid,
                                      uint64_t address,
                                      const std::vector<uint8_t>& bytes,
                                      std::string* out_error) {
        QString message;
        const int rc = runtime->DispatchWriteMemoryEvent(pid, address, bytes, timeout_ms, user_ctx, &message);
        if (rc == static_cast<int>(R3_MODULE_DISPATCH_HANDLED)) {
          return ClientService::OverrideAction::kHandled;
        }
        if (rc == static_cast<int>(R3_MODULE_DISPATCH_ERROR)) {
          if (out_error) {
            *out_error = ToStdString(message.trimmed().isEmpty() ? QStringLiteral("plugin write error")
                                                                 : message.trimmed());
          }
          return ClientService::OverrideAction::kError;
        }
        return ClientService::OverrideAction::kPass;
      };
  service->SetMemoryOverrideHooks(std::move(read_hook), std::move(write_hook));
}

bool ActivateRuntimeForMode(r3::windows_client_qt::plugins::PluginRuntime* runtime,
                            const r3::windows_client_qt::plugins::PluginManifest& manifest,
                            const char* read_mode,
                            const char* write_mode,
                            QString* out_error) {
  if (!runtime) {
    if (out_error) {
      *out_error = QStringLiteral("runtime null");
    }
    return false;
  }
  runtime->Deactivate();
  SetPluginMode(read_mode, write_mode);
  QString runtime_error;
  if (!runtime->Activate(manifest, &runtime_error)) {
    if (out_error) {
      *out_error = runtime_error;
    }
    return false;
  }
  if (!runtime->SupportsMemoryEvent()) {
    if (out_error) {
      *out_error = QStringLiteral("plugin has no memory event support");
    }
    runtime->Deactivate();
    return false;
  }
  return true;
}

void WriteReport(const QString& path,
                 const Config& cfg,
                 uint64_t read_addr,
                 uint64_t write_addr,
                 const std::vector<StepResult>& results) {
  if (path.trimmed().isEmpty()) {
    return;
  }
  QDir().mkpath(QFileInfo(path).absolutePath());
  QJsonObject root;
  root.insert(QStringLiteral("generated_at"), QDateTime::currentDateTime().toString(Qt::ISODate));
  root.insert(QStringLiteral("host"), cfg.host);
  root.insert(QStringLiteral("port"), static_cast<int>(cfg.port));
  root.insert(QStringLiteral("pid"), static_cast<int>(cfg.pid));
  root.insert(QStringLiteral("plugin_dll"), cfg.plugin_dll);
  root.insert(QStringLiteral("read_addr"), QStringLiteral("0x%1").arg(read_addr, 0, 16));
  root.insert(QStringLiteral("write_addr"), QStringLiteral("0x%1").arg(write_addr, 0, 16));
  int pass_count = 0;
  QJsonArray arr;
  for (const auto& r : results) {
    if (r.passed) {
      ++pass_count;
    }
    QJsonObject item;
    item.insert(QStringLiteral("name"), r.name);
    item.insert(QStringLiteral("passed"), r.passed);
    item.insert(QStringLiteral("detail"), r.detail);
    arr.push_back(item);
  }
  root.insert(QStringLiteral("pass_count"), pass_count);
  root.insert(QStringLiteral("total_count"), static_cast<int>(results.size()));
  root.insert(QStringLiteral("results"), arr);
  QFile f(path);
  if (f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();
  }
}

}  // namespace

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);
  Config cfg;
  QString parse_error;
  if (!ParseArgs(argc, argv, &cfg, &parse_error)) {
    std::cerr << ToStdString(parse_error) << "\n";
    return 2;
  }

  std::vector<StepResult> results;

  WSADATA wsa_data{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    std::cerr << "WSAStartup failed\n";
    return 3;
  }

  uint64_t read_addr = 0;
  uint64_t write_addr = 0;
  int exit_code = 0;

  r3::windows_client_ng::services::ClientService service;
  r3::windows_client_qt::plugins::PluginRuntime runtime;

  do {
    std::string error;
    const bool conn_ok = service.Connect(ToStdString(cfg.host), cfg.port, &error);
    AddResult(&results,
              QStringLiteral("service_connect"),
              conn_ok,
              conn_ok ? QStringLiteral("%1:%2").arg(cfg.host).arg(cfg.port)
                      : QStringLiteral("connect failed: %1").arg(ToQString(error)));
    if (!conn_ok) {
      exit_code = 1;
      break;
    }

    r3::windows_client_ng::services::ClientService::AgentCapabilities caps{};
    std::string caps_error;
    const bool caps_ok = service.FetchCapabilities(&caps, &caps_error);
    AddResult(&results,
              QStringLiteral("fetch_caps"),
              caps_ok,
              caps_ok ? QStringLiteral("proto=%1 flags=0x%2")
                            .arg(caps.protocol_version)
                            .arg(QString::number(static_cast<qulonglong>(caps.flags), 16))
                      : QStringLiteral("caps failed: %1").arg(ToQString(caps_error)));
    if (!caps_ok) {
      exit_code = 1;
      break;
    }

    std::string attach_error;
    const bool attach_ok = service.Attach(cfg.pid, &attach_error);
    AddResult(&results,
              QStringLiteral("service_attach"),
              attach_ok,
              attach_ok ? QStringLiteral("pid=%1").arg(cfg.pid)
                        : QStringLiteral("attach failed: %1").arg(ToQString(attach_error)));
    if (!attach_ok) {
      exit_code = 1;
      break;
    }

    std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo> modules;
    std::string module_error;
    const bool modules_ok = service.FetchModules(cfg.pid, &modules, &module_error);
    if (modules_ok) {
      for (const auto& m : modules) {
        if ((m.perms & protocol::MODULE_PERM_READ) != 0 && m.start != 0) {
          read_addr = m.start;
          break;
        }
      }
      for (const auto& m : modules) {
        if ((m.perms & protocol::MODULE_PERM_READ) != 0 && (m.perms & protocol::MODULE_PERM_WRITE) != 0 &&
            m.start != 0) {
          write_addr = m.start + 0x20u;
          break;
        }
      }
    }
    const bool addr_ok = modules_ok && read_addr != 0 && write_addr != 0;
    AddResult(&results,
              QStringLiteral("resolve_rw_addr"),
              addr_ok,
              addr_ok ? QStringLiteral("read=0x%1 write=0x%2").arg(read_addr, 0, 16).arg(write_addr, 0, 16)
                      : QStringLiteral("resolve failed: %1").arg(ToQString(module_error)));
    if (!addr_ok) {
      exit_code = 1;
      break;
    }

    r3::windows_client_qt::plugins::PluginManifest manifest;
    manifest.id = QStringLiteral("com.r3.e2e.override");
    manifest.name = QStringLiteral("R3 Override E2E Plugin");
    manifest.mode = QStringLiteral("in_process");
    manifest.entry = QFileInfo(cfg.plugin_dll).absoluteFilePath();
    manifest.capabilities = QStringList{QStringLiteral("memory.provider")};

    QString activate_error;
    const bool activate_pass =
        ActivateRuntimeForMode(&runtime, manifest, "pass", "pass", &activate_error);
    AddResult(&results,
              QStringLiteral("plugin_activate_pass"),
              activate_pass,
              activate_pass ? manifest.entry : QStringLiteral("activate failed: %1").arg(activate_error));
    if (!activate_pass) {
      exit_code = 1;
      break;
    }
    ConfigureOverrideHooks(&service, &runtime, 1000u, std::vector<uint8_t>{});
    std::vector<uint8_t> pass_read;
    std::string pass_read_error;
    const bool pass_read_ok = service.ReadMemory(read_addr, 8u, true, &pass_read, &pass_read_error);
    AddResult(&results,
              QStringLiteral("scenario_pass_read"),
              pass_read_ok && pass_read.size() == 8u,
              pass_read_ok ? QStringLiteral("bytes=%1").arg(pass_read.size())
                           : QStringLiteral("read failed: %1").arg(ToQString(pass_read_error)));

    std::string pass_write_error;
    const std::vector<uint8_t> pass_write_bytes = pass_read.size() >= 4u
                                                      ? std::vector<uint8_t>(pass_read.begin(), pass_read.begin() + 4)
                                                      : std::vector<uint8_t>{0x11, 0x22, 0x33, 0x44};
    const bool pass_write_ok = service.WriteMemory(write_addr, pass_write_bytes, &pass_write_error);
    AddResult(&results,
              QStringLiteral("scenario_pass_write"),
              pass_write_ok,
              pass_write_ok ? QStringLiteral("write addr=0x%1").arg(write_addr, 0, 16)
                            : QStringLiteral("write failed: %1").arg(ToQString(pass_write_error)));
    service.ClearMemoryOverrideHooks();
    runtime.Deactivate();

    const bool pass_phase_ok = pass_read_ok && pass_read.size() == 8u && pass_write_ok;
    AddResult(&results,
              QStringLiteral("scenario_pass_summary"),
              pass_phase_ok,
              pass_phase_ok ? QStringLiteral("PASS flow uses default path") : QStringLiteral("PASS flow failed"));
    if (!pass_phase_ok) {
      exit_code = 1;
      break;
    }

    const bool activate_handled =
        ActivateRuntimeForMode(&runtime, manifest, "handled", "handled", &activate_error);
    AddResult(&results,
              QStringLiteral("plugin_activate_handled"),
              activate_handled,
              activate_handled ? manifest.entry : QStringLiteral("activate failed: %1").arg(activate_error));
    if (!activate_handled) {
      exit_code = 1;
      break;
    }
    ConfigureOverrideHooks(&service, &runtime, 1000u, std::vector<uint8_t>{});
    std::vector<uint8_t> handled_read;
    std::string handled_read_error;
    const bool handled_read_ok = service.ReadMemory(1u, 8u, true, &handled_read, &handled_read_error);
    const bool handled_pattern_ok =
        handled_read_ok && handled_read.size() == 8u &&
        std::all_of(handled_read.begin(), handled_read.end(), [](uint8_t b) { return b == 0xAB; });
    AddResult(&results,
              QStringLiteral("scenario_handled_read"),
              handled_pattern_ok,
              handled_read_ok ? QStringLiteral("bytes=%1 first=0x%2")
                                    .arg(handled_read.size())
                                    .arg(handled_read.empty() ? QStringLiteral("--")
                                                              : QString::number(handled_read[0], 16))
                              : QStringLiteral("read failed: %1").arg(ToQString(handled_read_error)));

    std::string handled_write_error;
    const bool handled_write_ok = service.WriteMemory(1u, std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF},
                                                      &handled_write_error);
    AddResult(&results,
              QStringLiteral("scenario_handled_write"),
              handled_write_ok,
              handled_write_ok ? QStringLiteral("invalid addr still handled by plugin")
                               : QStringLiteral("write failed: %1").arg(ToQString(handled_write_error)));
    service.ClearMemoryOverrideHooks();
    runtime.Deactivate();

    const bool handled_phase_ok = handled_pattern_ok && handled_write_ok;
    AddResult(&results,
              QStringLiteral("scenario_handled_summary"),
              handled_phase_ok,
              handled_phase_ok ? QStringLiteral("HANDLED flow overrides default path")
                               : QStringLiteral("HANDLED flow failed"));
    if (!handled_phase_ok) {
      exit_code = 1;
      break;
    }

    const bool activate_error_mode =
        ActivateRuntimeForMode(&runtime, manifest, "error", "error", &activate_error);
    AddResult(&results,
              QStringLiteral("plugin_activate_error"),
              activate_error_mode,
              activate_error_mode ? manifest.entry
                                  : QStringLiteral("activate failed: %1").arg(activate_error));
    if (!activate_error_mode) {
      exit_code = 1;
      break;
    }
    ConfigureOverrideHooks(&service, &runtime, 1000u, std::vector<uint8_t>{});
    std::vector<uint8_t> error_read;
    std::string error_read_text;
    const bool error_read_ok = service.ReadMemory(read_addr, 4u, true, &error_read, &error_read_text);
    const bool error_read_match = !error_read_ok && ContainsText(error_read_text, "read forced error");
    AddResult(&results,
              QStringLiteral("scenario_error_read"),
              error_read_match,
              error_read_ok ? QStringLiteral("unexpected success")
                            : QStringLiteral("error=%1").arg(ToQString(error_read_text)));

    std::string error_write_text;
    const bool error_write_ok = service.WriteMemory(write_addr, std::vector<uint8_t>{0xAA}, &error_write_text);
    const bool error_write_match = !error_write_ok && ContainsText(error_write_text, "write forced error");
    AddResult(&results,
              QStringLiteral("scenario_error_write"),
              error_write_match,
              error_write_ok ? QStringLiteral("unexpected success")
                             : QStringLiteral("error=%1").arg(ToQString(error_write_text)));
    service.ClearMemoryOverrideHooks();
    runtime.Deactivate();

    const bool error_phase_ok = error_read_match && error_write_match;
    AddResult(&results,
              QStringLiteral("scenario_error_summary"),
              error_phase_ok,
              error_phase_ok ? QStringLiteral("ERROR flow blocks default path")
                             : QStringLiteral("ERROR flow failed"));
    if (!error_phase_ok) {
      exit_code = 1;
      break;
    }
  } while (false);

  const int passed = static_cast<int>(
      std::count_if(results.begin(), results.end(), [](const StepResult& r) { return r.passed; }));
  const int total = static_cast<int>(results.size());
  std::cout << "Summary: " << passed << "/" << total << " passed\n";

  WriteReport(cfg.out_json, cfg, read_addr, write_addr, results);
  runtime.Deactivate();
  service.ClearMemoryOverrideHooks();
  service.Disconnect();
  WSACleanup();
  return exit_code == 0 ? 0 : 1;
}

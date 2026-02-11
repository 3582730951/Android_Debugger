#pragma once

#include <optional>
#include <vector>

#include <QString>
#include <QStringList>

namespace r3::windows_client_qt::plugins {

struct QuickstartField {
  QString id;
  QString label;
  QString type;
  QString default_value;
  QString description;
};

struct PluginManifest {
  QString id;
  QString name;
  QString version;
  QString description;
  QString plugin_dir;
  QString mode;
  QString entry;
  QStringList oop_args;
  QString abi;
  QString min_host_version;
  QString max_host_version;
  QStringList supported_arch;
  int priority = 100;
  QStringList capabilities;
  int syscall_read = -1;
  int syscall_write = -1;
  int timeout_ms = 1000;
  QString default_user_ctx_hex;
  std::vector<QuickstartField> quickstart_fields;
};

class PluginCatalog {
 public:
  bool LoadFromRoot(const QString& root_path, QString* out_error);
  const std::vector<PluginManifest>& Plugins() const { return plugins_; }
  int LastLoadedCount() const { return last_loaded_count_; }
  int LastFailedCount() const { return last_failed_count_; }
  const QStringList& LastFailureMessages() const { return last_failure_messages_; }
  std::optional<PluginManifest> FindById(const QString& id) const;

 private:
  std::vector<PluginManifest> plugins_;
  int last_loaded_count_ = 0;
  int last_failed_count_ = 0;
  QStringList last_failure_messages_;
};

}  // namespace r3::windows_client_qt::plugins

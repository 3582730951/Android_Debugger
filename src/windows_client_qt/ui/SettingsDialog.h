#pragma once

#include <cstdint>
#include <vector>

#include <QDialog>

#include "plugins/PluginCatalog.h"

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QWidget;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class SettingsDialog : public QDialog {
  Q_OBJECT

 public:
  struct SettingsData {
    QString host;
    uint16_t port = 12345;
    QString adb_path;
    bool auto_start = true;
    int default_value_type = 0;
    int default_compare_type = 0;
    int value_refresh_ms = 450;
    QString plugin_root_path;
    QString plugin_id;
    bool plugin_enabled = false;
    bool plugin_allow_fallback = true;
    int plugin_timeout_ms = 1000;
    int plugin_syscall_read = -1;
    int plugin_syscall_write = -1;
    QString plugin_user_ctx_hex;
  };

  explicit SettingsDialog(QWidget* parent = nullptr);

  void SetPluginEntries(const std::vector<r3::windows_client_qt::plugins::PluginManifest>& plugins);
  void SetData(const SettingsData& data);
  SettingsData Data() const;
  void SetPluginSectionVisible(bool visible);

 signals:
  void OpenPluginDevWindowRequested();

 private:
  void BuildUi();
  void OnPluginSelectionChanged(int index);
  void OnGenerateUserCtxFromQuickstart();
  void OnScanPluginsClicked();

  QLineEdit* host_edit_ = nullptr;
  QSpinBox* port_spin_ = nullptr;
  QLineEdit* adb_edit_ = nullptr;
  QCheckBox* auto_start_check_ = nullptr;
  QComboBox* default_value_type_combo_ = nullptr;
  QComboBox* default_compare_combo_ = nullptr;
  QSpinBox* refresh_interval_spin_ = nullptr;
  QWidget* plugin_dev_entry_row_ = nullptr;
  QPushButton* open_plugin_dev_button_ = nullptr;
  QGroupBox* plugin_group_ = nullptr;

  QLineEdit* plugin_root_edit_ = nullptr;
  QPushButton* plugin_scan_button_ = nullptr;
  QComboBox* plugin_combo_ = nullptr;
  QCheckBox* plugin_enable_check_ = nullptr;
  QCheckBox* plugin_fallback_check_ = nullptr;
  QSpinBox* plugin_timeout_spin_ = nullptr;
  QSpinBox* plugin_syscall_read_spin_ = nullptr;
  QSpinBox* plugin_syscall_write_spin_ = nullptr;
  QLineEdit* plugin_user_ctx_edit_ = nullptr;
  QLabel* plugin_desc_label_ = nullptr;
  QPlainTextEdit* plugin_quickstart_view_ = nullptr;
  QPlainTextEdit* plugin_quickstart_input_ = nullptr;
  QPushButton* plugin_generate_ctx_button_ = nullptr;

  std::vector<r3::windows_client_qt::plugins::PluginManifest> plugin_entries_;
};

}  // namespace r3::windows_client_qt::ui

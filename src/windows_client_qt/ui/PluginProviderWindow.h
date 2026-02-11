#pragma once

#include <vector>

#include <QDialog>

#include "plugins/PluginCatalog.h"

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class PluginProviderWindow : public QDialog {
  Q_OBJECT

 public:
  struct ProviderSettings {
    QString plugin_root_path;
    QString plugin_id;
    bool plugin_enabled = false;
    bool plugin_allow_fallback = true;
    int plugin_timeout_ms = 1000;
    int plugin_syscall_read = -1;
    int plugin_syscall_write = -1;
    QString plugin_user_ctx_hex;
  };

  explicit PluginProviderWindow(QWidget* parent = nullptr);

  void SetPluginEntries(const std::vector<r3::windows_client_qt::plugins::PluginManifest>& plugins);
  void SetData(const ProviderSettings& data);
  ProviderSettings Data() const;

 signals:
  void OpenPluginDevWindowRequested();

 private:
  void BuildUi();
  void OnPluginSelectionChanged(int index);
  void OnGenerateUserCtxFromQuickstart();
  void OnScanPluginsClicked();
  void OnOpenPluginRootClicked();

  QLabel* workflow_label_ = nullptr;
  QPushButton* open_plugin_dev_button_ = nullptr;
  QPushButton* open_plugin_root_button_ = nullptr;
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

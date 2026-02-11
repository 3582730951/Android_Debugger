#pragma once

#include <QDialog>
#include <QString>

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class PluginRuntimeWindow : public QDialog {
  Q_OBJECT

 public:
  explicit PluginRuntimeWindow(QWidget* parent = nullptr);

  void SetRuntimeState(const QString& module_status,
                       int loaded_count,
                       int failed_count,
                       double avg_elapsed_ms,
                       bool force_builtin_fallback);

 signals:
  void PluginSelfCheckRequested();
  void PluginFallbackToggleRequested();

 private:
  QLabel* module_status_label_ = nullptr;
  QLabel* load_count_label_ = nullptr;
  QLabel* failed_count_label_ = nullptr;
  QLabel* avg_latency_label_ = nullptr;
  QPushButton* self_check_button_ = nullptr;
  QPushButton* fallback_button_ = nullptr;
};

}  // namespace r3::windows_client_qt::ui

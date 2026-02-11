#pragma once

#include <QDialog>
#include <QStringList>

QT_BEGIN_NAMESPACE
class QLabel;
class QPlainTextEdit;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class PluginFailureWindow : public QDialog {
  Q_OBJECT

 public:
  explicit PluginFailureWindow(QWidget* parent = nullptr);

  void SetSummary(int loaded_count, int failed_count, double avg_elapsed_ms);
  void SetFailureMessages(const QStringList& messages);

 private:
  QLabel* summary_label_ = nullptr;
  QPlainTextEdit* output_view_ = nullptr;
};

}  // namespace r3::windows_client_qt::ui

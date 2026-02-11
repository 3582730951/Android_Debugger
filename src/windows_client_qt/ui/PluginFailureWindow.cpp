#include "ui/PluginFailureWindow.h"

#include <QLabel>
#include <QPlainTextEdit>
#include <QVBoxLayout>

namespace r3::windows_client_qt::ui {

PluginFailureWindow::PluginFailureWindow(QWidget* parent) : QDialog(parent) {
  setWindowTitle(QStringLiteral("插件加载失败输出"));
  resize(860, 520);

  auto* root = new QVBoxLayout(this);
  summary_label_ = new QLabel(QStringLiteral("插件加载数量: 0 | 插件加载失败数量: 0 | 插件平均耗时: 0.000 ms"), this);
  output_view_ = new QPlainTextEdit(this);
  output_view_->setReadOnly(true);
  output_view_->setPlaceholderText(QStringLiteral("暂无插件加载失败输出"));
  root->addWidget(summary_label_);
  root->addWidget(output_view_, 1);
}

void PluginFailureWindow::SetSummary(int loaded_count, int failed_count, double avg_elapsed_ms) {
  if (!summary_label_) {
    return;
  }
  summary_label_->setText(
      QStringLiteral("插件加载数量: %1 | 插件加载失败数量: %2 | 插件平均耗时: %3 ms")
          .arg(loaded_count)
          .arg(failed_count)
          .arg(QString::number(avg_elapsed_ms, 'f', 3)));
}

void PluginFailureWindow::SetFailureMessages(const QStringList& messages) {
  if (!output_view_) {
    return;
  }
  if (messages.isEmpty()) {
    output_view_->setPlainText(QStringLiteral("暂无插件加载失败输出"));
    return;
  }
  output_view_->setPlainText(messages.join('\n'));
}

}  // namespace r3::windows_client_qt::ui


#include "ui/PluginRuntimeWindow.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace r3::windows_client_qt::ui {

PluginRuntimeWindow::PluginRuntimeWindow(QWidget* parent) : QDialog(parent) {
  setWindowTitle(QStringLiteral("插件运行状态"));
  resize(640, 280);

  auto* root = new QVBoxLayout(this);

  auto* group = new QGroupBox(QStringLiteral("插件运行状态"), this);
  auto* form = new QFormLayout(group);

  module_status_label_ = new QLabel(QStringLiteral("未启用"), group);
  module_status_label_->setWordWrap(true);
  load_count_label_ = new QLabel(QStringLiteral("0"), group);
  failed_count_label_ = new QLabel(QStringLiteral("0"), group);
  avg_latency_label_ = new QLabel(QStringLiteral("0.000 ms"), group);
  self_check_button_ = new QPushButton(QStringLiteral("插件自检"), group);
  fallback_button_ = new QPushButton(QStringLiteral("立即回退内置provider"), group);

  auto* btn_row = new QHBoxLayout();
  btn_row->addWidget(self_check_button_);
  btn_row->addWidget(fallback_button_);

  form->addRow(QStringLiteral("模块状态:"), module_status_label_);
  form->addRow(QStringLiteral("插件加载数量:"), load_count_label_);
  form->addRow(QStringLiteral("插件加载失败数量:"), failed_count_label_);
  form->addRow(QStringLiteral("插件平均耗时:"), avg_latency_label_);
  form->addRow(QString(), btn_row);

  root->addWidget(group, 1);

  connect(self_check_button_, &QPushButton::clicked, this, [this]() { emit PluginSelfCheckRequested(); });
  connect(fallback_button_, &QPushButton::clicked, this, [this]() { emit PluginFallbackToggleRequested(); });
}

void PluginRuntimeWindow::SetRuntimeState(const QString& module_status,
                                          int loaded_count,
                                          int failed_count,
                                          double avg_elapsed_ms,
                                          bool force_builtin_fallback) {
  if (module_status_label_) {
    module_status_label_->setText(module_status.trimmed().isEmpty() ? QStringLiteral("-") : module_status.trimmed());
  }
  if (load_count_label_) {
    load_count_label_->setText(QString::number(loaded_count));
  }
  if (failed_count_label_) {
    failed_count_label_->setText(QString::number(failed_count));
  }
  if (avg_latency_label_) {
    avg_latency_label_->setText(QStringLiteral("%1 ms").arg(QString::number(avg_elapsed_ms, 'f', 3)));
  }
  if (fallback_button_) {
    fallback_button_->setText(force_builtin_fallback ? QStringLiteral("恢复插件provider")
                                                     : QStringLiteral("立即回退内置provider"));
  }
}

}  // namespace r3::windows_client_qt::ui

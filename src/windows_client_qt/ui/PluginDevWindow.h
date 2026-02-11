#pragma once

#include <QDialog>

namespace r3::windows_client_qt::ui {

class PluginDevWindow : public QDialog {
  Q_OBJECT

 public:
  explicit PluginDevWindow(QWidget* parent = nullptr);
};

}  // namespace r3::windows_client_qt::ui


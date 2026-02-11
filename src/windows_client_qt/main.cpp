#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include <objbase.h>

#include <QApplication>
#include <QFile>

#include "ui/MainWindow.h"

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
  WSADATA wsa_data{};
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    return 1;
  }

  HRESULT com_hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(com_hr)) {
    WSACleanup();
    return 2;
  }

  int argc = 0;
  QApplication app(argc, nullptr);
  app.setApplicationName(QStringLiteral("R3 Android Debug Client"));
  app.setOrganizationName(QStringLiteral("R3"));

  const QString style =
      "QMainWindow, QDialog { background: #1f232a; color: #e4e7ee; }"
      "QWidget { color: #e4e7ee; }"
      "QMenuBar, QMenu, QStatusBar { background: #1b1e24; color: #dfe3ec; }"
      "QMenuBar::item { padding: 6px 12px; margin: 0 2px; }"
      "QMenu::item { padding: 7px 28px 7px 12px; min-height: 24px; }"
      "QToolBar { background: #1b1e24; border: 0; spacing: 6px; }"
      "QPushButton { background: #2a313c; border: 1px solid #3a4352; padding: 5px 10px; }"
      "QPushButton:hover { background: #333c4a; }"
      "QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {"
      " background: #171a20; border: 1px solid #3a4352; selection-background-color: #375a9e; }"
      "QTableView { background: #16191f; gridline-color: #2f3642; alternate-background-color: #1b2028; }"
      "QHeaderView::section { background: #252c36; border: 0; padding: 4px; }"
      "QTabWidget::pane { border: 1px solid #353d4c; }"
      "QTabBar::tab { background: #242a34; padding: 6px 10px; }"
      "QTabBar::tab:selected { background: #313946; }";
  app.setStyleSheet(style);

  r3::windows_client_qt::ui::MainWindow window;
  window.show();

  const int rc = app.exec();
  CoUninitialize();
  WSACleanup();
  return rc;
}

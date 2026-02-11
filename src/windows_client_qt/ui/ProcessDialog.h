#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <QDialog>
#include <QSortFilterProxyModel>

#include "services/ClientService.h"

QT_BEGIN_NAMESPACE
class QLabel;
class QIcon;
class QLineEdit;
class QPushButton;
class QTableView;
class QStandardItemModel;
class QTabWidget;
class QTimer;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class ProcessDialog : public QDialog {
  Q_OBJECT

 public:
  struct ProcessSelection {
    uint32_t pid = 0;
    QString name;
  };

  explicit ProcessDialog(QWidget* parent = nullptr);

  void SetProcesses(const std::vector<r3::windows_client_ng::services::ProcessInfo>& processes);
  void SetBusyText(const QString& text);
  bool IsLoading() const;
  void SetLoading(bool loading);

  void UpdateIcon(uint32_t pid, const QIcon& icon);

  std::optional<ProcessSelection> SelectedProcess() const;

 private:
  class ProcessFilterProxy final : public QSortFilterProxyModel {
   public:
    explicit ProcessFilterProxy(QObject* parent = nullptr);

    void SetKeyword(const QString& keyword);
    void SetShowSystem(bool show_system);

   protected:
    bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;

   private:
    QString keyword_;
    bool show_system_ = false;
  };

  static bool IsSystemProcess(uint32_t pid, const QString& name);

 private slots:
  void OnTabChanged(int index);
  void OnFilterChanged(const QString& text);
  void OnOpenClicked();

 private:
  void BuildUi();
  void AppendProcessRowsChunk();
  void UpdateStatusText();

  QTabWidget* tabs_ = nullptr;
  QLineEdit* filter_edit_ = nullptr;
  QLabel* status_label_ = nullptr;
  QTableView* table_ = nullptr;
  QStandardItemModel* source_model_ = nullptr;
  ProcessFilterProxy* proxy_model_ = nullptr;
  QTimer* append_timer_ = nullptr;
  QPushButton* open_button_ = nullptr;
  QPushButton* cancel_button_ = nullptr;

  bool loading_ = false;
  std::vector<r3::windows_client_ng::services::ProcessInfo> pending_processes_;
  int pending_row_index_ = 0;
};

}  // namespace r3::windows_client_qt::ui

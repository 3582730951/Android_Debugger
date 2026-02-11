#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <QDialog>
#include <QSortFilterProxyModel>

#include "services/ClientService.h"

QT_BEGIN_NAMESPACE
class QLineEdit;
class QLabel;
class QTableView;
class QStandardItemModel;
QT_END_NAMESPACE

namespace r3::windows_client_qt::ui {

class ModuleRangeDialog : public QDialog {
  Q_OBJECT

 public:
  struct RangeResult {
    uint64_t start = 0;
    uint64_t end = 0;
    QString path;
  };

  explicit ModuleRangeDialog(QWidget* parent = nullptr);

  void SetModules(const std::vector<r3::windows_client_ng::services::ClientService::ModuleInfo>& modules);
  void SetFooterText(const QString& text);
  std::optional<RangeResult> SelectedRange() const;

 private slots:
  void OnFilterTextChanged(const QString& text);
  void OnApplyClicked();

 private:
  class ModuleFilterProxy final : public QSortFilterProxyModel {
   public:
    explicit ModuleFilterProxy(QObject* parent = nullptr);

    void SetKeyword(const QString& keyword);

   protected:
    bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;

   private:
    QString keyword_;
  };

 private:
  void BuildUi();

  QLineEdit* filter_edit_ = nullptr;
  QLabel* footer_label_ = nullptr;
  QTableView* table_ = nullptr;
  QStandardItemModel* source_model_ = nullptr;
  ModuleFilterProxy* proxy_model_ = nullptr;
};

}  // namespace r3::windows_client_qt::ui

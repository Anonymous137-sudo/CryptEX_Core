#pragma once

#include <QDialog>

class QWidget;

class WalletManagerWindow : public QDialog {
    Q_OBJECT
public:
    explicit WalletManagerWindow(QWidget* parent = nullptr);

    void setPage(QWidget* page);
    void showWindow();

private:
    QWidget* content_{nullptr};
};

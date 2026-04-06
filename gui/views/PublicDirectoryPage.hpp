#pragma once

#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class RpcClient;

class PublicDirectoryPage : public QWidget {
    Q_OBJECT
public:
    explicit PublicDirectoryPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    static QString formatCoins(qint64 sats);
    static QString formatTimestamp(qint64 unixTs);
    void setStatus(const QString& text, bool error = false);
    void applyFilter();
    void refreshStatusSummary(int rowCount);

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QLineEdit* filterEdit_{nullptr};
    QTableWidget* table_{nullptr};
    QPushButton* refreshButton_{nullptr};
    bool walletLoaded_{false};
};

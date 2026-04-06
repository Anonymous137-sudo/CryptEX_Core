#pragma once

#include <QJsonObject>
#include <QVector>
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

signals:
    void messageRequested(const QString& address,
                          const QString& pubkeyB64,
                          const QString& peer);
    void callRequested(const QString& address,
                       const QString& pubkeyB64,
                       const QString& peer);

private:
    static QString formatCoins(qint64 sats);
    static QString formatTimestamp(qint64 unixTs);
    void setStatus(const QString& text, bool error = false);
    void applyFilter();
    void refreshStatusSummary(int rowCount);
    void updateActionState();
    QJsonObject selectedEntry() const;
    void messageSelectedAddress();
    void callSelectedAddress();
    void saveSelectedAddress();

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QLineEdit* filterEdit_{nullptr};
    QTableWidget* table_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* messageButton_{nullptr};
    QPushButton* callButton_{nullptr};
    QPushButton* saveContactButton_{nullptr};
    bool walletLoaded_{false};
    QVector<QJsonObject> entries_;
};

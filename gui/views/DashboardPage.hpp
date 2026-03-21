#pragma once

#include <QWidget>

class QLabel;
class RpcClient;
class QListWidget;

class DashboardPage : public QWidget {
    Q_OBJECT
public:
    explicit DashboardPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    static QString formatHashrate(double hps);
    static QString formatCoins(qint64 sats);
    void setStatus(const QString& text, bool error = false);

    RpcClient* rpc_{nullptr};
    QLabel* availableValue_{nullptr};
    QLabel* pendingValue_{nullptr};
    QLabel* totalValue_{nullptr};
    QLabel* networkValue_{nullptr};
    QLabel* blocksValue_{nullptr};
    QLabel* bestHashValue_{nullptr};
    QLabel* connectionsValue_{nullptr};
    QLabel* peersValue_{nullptr};
    QLabel* difficultyValue_{nullptr};
    QLabel* mempoolValue_{nullptr};
    QLabel* endpointValue_{nullptr};
    QLabel* hashrateValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QListWidget* recentTransactions_{nullptr};
};

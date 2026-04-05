#pragma once

#include <QWidget>

class QLabel;
class RpcClient;
class QListWidget;
class QBoxLayout;
class QResizeEvent;

class DashboardPage : public QWidget {
    Q_OBJECT
public:
    explicit DashboardPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

protected:
    void resizeEvent(QResizeEvent* event) override;

private:
    static QString formatHashrate(double hps);
    static QString formatCoins(qint64 sats);
    void setStatus(const QString& text, bool error = false);
    void updateResponsiveLayout();

    RpcClient* rpc_{nullptr};
    QBoxLayout* topRowLayout_{nullptr};
    QLabel* availableValue_{nullptr};
    QLabel* pendingValue_{nullptr};
    QLabel* lockedValue_{nullptr};
    QLabel* totalValue_{nullptr};
    QLabel* approvalValue_{nullptr};
    QLabel* networkValue_{nullptr};
    QLabel* blocksValue_{nullptr};
    QLabel* bestHashValue_{nullptr};
    QLabel* connectionsValue_{nullptr};
    QLabel* validatedPeersValue_{nullptr};
    QLabel* peersValue_{nullptr};
    QLabel* difficultyValue_{nullptr};
    QLabel* mempoolValue_{nullptr};
    QLabel* endpointValue_{nullptr};
    QLabel* hashrateValue_{nullptr};
    QLabel* syncValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QListWidget* recentTransactions_{nullptr};
};

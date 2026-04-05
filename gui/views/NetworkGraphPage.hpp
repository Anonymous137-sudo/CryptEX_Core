#pragma once

#include <QWidget>

class QLabel;
class RpcClient;
class QTableWidget;

class NetworkGraphPage : public QWidget {
    Q_OBJECT
public:
    explicit NetworkGraphPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void setStatus(const QString& text, bool error = false);
    void appendSample(double blocks, double connections, double hashrate);
    QString formatHashrate(double hps) const;
    QString formatCoins(qint64 sats) const;

    RpcClient* rpc_{nullptr};
    QWidget* graph_{nullptr};
    QWidget* topology_{nullptr};
    QLabel* snapshotLabel_{nullptr};
    QLabel* approvalLabel_{nullptr};
    QLabel* lockedLabel_{nullptr};
    QLabel* peersLabel_{nullptr};
    QLabel* checkpointLabel_{nullptr};
    QLabel* mappingLabel_{nullptr};
    QTableWidget* peerTable_{nullptr};
    QLabel* statusLabel_{nullptr};
};

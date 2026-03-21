#pragma once

#include <QWidget>

class QLabel;
class RpcClient;

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

    RpcClient* rpc_{nullptr};
    QWidget* graph_{nullptr};
    QLabel* snapshotLabel_{nullptr};
    QLabel* statusLabel_{nullptr};
};

#pragma once

#include <QWidget>

class QLabel;
class QCheckBox;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;
class RpcClient;

class TransactionsPage : public QWidget {
    Q_OBJECT
public:
    explicit TransactionsPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    static QString formatCoins(qint64 sats);
    static QString formatTimestamp(qint64 timestamp);
    void setStatus(const QString& text, bool error = false);
    void requestTransactionDetail(const QString& txid);

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QCheckBox* includeMempoolCheck_{nullptr};
    QTableWidget* historyTable_{nullptr};
    QPlainTextEdit* detailView_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QString detailTxid_;
};

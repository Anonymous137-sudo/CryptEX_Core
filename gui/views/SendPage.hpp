#pragma once

#include <QWidget>

class QLabel;
class QDoubleSpinBox;
class QLineEdit;
class QPushButton;
class RpcClient;

class SendPage : public QWidget {
    Q_OBJECT
public:
    explicit SendPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    static QString formatCoins(qint64 sats);
    void setStatus(const QString& text, bool error = false);
    void sendPayment();

    RpcClient* rpc_{nullptr};
    QLabel* walletTypeValue_{nullptr};
    QLabel* approvalValue_{nullptr};
    QLabel* spendableValue_{nullptr};
    QLabel* lockedValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QLineEdit* sendToEdit_{nullptr};
    QDoubleSpinBox* amountSpin_{nullptr};
    QLineEdit* opReturnEdit_{nullptr};
    QPushButton* sendButton_{nullptr};
    QPushButton* refreshButton_{nullptr};
    bool chainApproved_{false};
};

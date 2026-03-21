#pragma once

#include <QWidget>

class QLabel;
class QCheckBox;
class QDoubleSpinBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;
class RpcClient;

class WalletPage : public QWidget {
    Q_OBJECT
public:
    explicit WalletPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    static QString formatCoins(qint64 sats);
    void setStatus(const QString& text, bool error = false);
    void requestNewAddress();
    void requestMnemonic();
    void requestRescan();
    void sendPayment();

    RpcClient* rpc_{nullptr};
    QLabel* modeValue_{nullptr};
    QLabel* primaryValue_{nullptr};
    QLabel* addressCountValue_{nullptr};
    QLabel* spendableValue_{nullptr};
    QLabel* immatureValue_{nullptr};
    QLabel* totalValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QTableWidget* addressTable_{nullptr};
    QTableWidget* utxoTable_{nullptr};
    QTableWidget* historyTable_{nullptr};
    QLineEdit* sendToEdit_{nullptr};
    QLineEdit* opReturnEdit_{nullptr};
    QDoubleSpinBox* sendAmountSpin_{nullptr};
    QCheckBox* includeMempoolCheck_{nullptr};
    QPlainTextEdit* mnemonicView_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* newAddressButton_{nullptr};
    QPushButton* rescanButton_{nullptr};
    QPushButton* mnemonicButton_{nullptr};
    QPushButton* sendButton_{nullptr};
};

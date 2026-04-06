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

signals:
    void walletTypeChanged();

private:
    static QString formatCoins(qint64 sats);
    static QString formatTimestamp(qint64 timestamp);
    void setStatus(const QString& text, bool error = false);
    QString selectAddressFormat(const QString& title);
    QString addressFromObject(const QJsonObject& obj, const QString& baseKey) const;
    void requestWalletTypeChange();
    void requestNewAddress();
    void requestMnemonic();
    void requestRescan();
    void requestPrimaryAddressChange();
    void saveLabel();
    void sendPayment();
    void requestTransactionDetail(const QString& txid);
    void syncLabelEditorFromSelection();
    QString selectedAddressKey() const;
    QString selectedHistoryTxid() const;
    void restoreAddressSelection(const QString& addressKey);
    void restoreHistorySelection(const QString& txid);

    RpcClient* rpc_{nullptr};
    QLabel* modeValue_{nullptr};
    QLabel* formatValue_{nullptr};
    QLabel* displayFormatValue_{nullptr};
    QLabel* primaryValue_{nullptr};
    QLabel* addressCountValue_{nullptr};
    QLabel* approvalValue_{nullptr};
    QLabel* spendableValue_{nullptr};
    QLabel* immatureValue_{nullptr};
    QLabel* lockedValue_{nullptr};
    QLabel* totalValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QTableWidget* addressTable_{nullptr};
    QTableWidget* utxoTable_{nullptr};
    QTableWidget* historyTable_{nullptr};
    QLineEdit* labelAddressEdit_{nullptr};
    QLineEdit* labelEdit_{nullptr};
    QLineEdit* sendToEdit_{nullptr};
    QLineEdit* changeAddressEdit_{nullptr};
    QLineEdit* opReturnEdit_{nullptr};
    QDoubleSpinBox* sendAmountSpin_{nullptr};
    QCheckBox* includeMempoolCheck_{nullptr};
    QPlainTextEdit* mnemonicView_{nullptr};
    QPlainTextEdit* txDetailView_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* changeWalletTypeButton_{nullptr};
    QPushButton* newAddressButton_{nullptr};
    QPushButton* rescanButton_{nullptr};
    QPushButton* mnemonicButton_{nullptr};
    QPushButton* setPrimaryButton_{nullptr};
    QPushButton* saveLabelButton_{nullptr};
    QPushButton* sendButton_{nullptr};
    bool chainApproved_{true};
    int refreshGeneration_{0};
    QString detailTxid_;
    QString preferredAddressFormat_{QStringLiteral("base64")};
    QString currentWalletFormat_{QStringLiteral("base64")};
};

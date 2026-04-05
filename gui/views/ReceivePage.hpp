#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QPlainTextEdit;
class QTableWidget;
class RpcClient;

class ReceivePage : public QWidget {
    Q_OBJECT
public:
    explicit ReceivePage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void setStatus(const QString& text, bool error = false);
    QString selectAddressFormat(const QString& title);
    void requestNewAddress();
    void requestUnusedAddress();
    void copyPrimaryAddress();
    QString addressFromObject(const QJsonObject& obj, const QString& baseKey) const;

    RpcClient* rpc_{nullptr};
    QLabel* walletTypeValue_{nullptr};
    QLabel* displayFormatValue_{nullptr};
    QLabel* addressCountValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QPlainTextEdit* primaryAddressView_{nullptr};
    QTableWidget* addressTable_{nullptr};
    QPushButton* newAddressButton_{nullptr};
    QPushButton* unusedAddressButton_{nullptr};
    QPushButton* copyAddressButton_{nullptr};
    QString preferredAddressFormat_{QStringLiteral("base64")};
    QString currentWalletFormat_{QStringLiteral("base64")};
};

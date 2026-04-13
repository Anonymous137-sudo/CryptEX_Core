#pragma once

#include <QVector>
#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;
class RpcClient;
class QJsonObject;

class MailAccountsPage : public QWidget {
    Q_OBJECT
public:
    explicit MailAccountsPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void setStatus(const QString& text, bool error = false);
    void copySelectedAlias();

    RpcClient* rpc_{nullptr};
    QVector<QJsonObject> entries_;
    QLabel* statusValue_{nullptr};
    QTableWidget* table_{nullptr};
    QPushButton* refreshButton_{nullptr};
    QPushButton* copyButton_{nullptr};
};

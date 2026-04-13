#pragma once

#include <QWidget>

class QLabel;
class QLineEdit;
class QCheckBox;
class QPushButton;
class RpcClient;

class MailAccountCreatePage : public QWidget {
    Q_OBJECT
public:
    explicit MailAccountCreatePage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

signals:
    void accountCreated();

private:
    void setStatus(const QString& text, bool error = false);
    void createAccount();
    void copyAlias();

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QLabel* aliasValue_{nullptr};
    QLineEdit* labelEdit_{nullptr};
    QCheckBox* setPrimaryCheck_{nullptr};
    QPushButton* createButton_{nullptr};
    QPushButton* copyButton_{nullptr};
};

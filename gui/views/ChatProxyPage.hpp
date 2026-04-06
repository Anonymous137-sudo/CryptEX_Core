#pragma once

#include <QWidget>

class QLabel;
class QCheckBox;
class QLineEdit;
class QSpinBox;
class QPushButton;
class RpcClient;

class ChatProxyPage : public QWidget {
    Q_OBJECT
public:
    explicit ChatProxyPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void setStatus(const QString& text, bool error = false);
    void save();

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QCheckBox* enabledCheck_{nullptr};
    QLineEdit* hostEdit_{nullptr};
    QSpinBox* portSpin_{nullptr};
    QCheckBox* remoteDnsCheck_{nullptr};
    QPushButton* saveButton_{nullptr};
    QPushButton* refreshButton_{nullptr};
};

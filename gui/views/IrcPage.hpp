#pragma once

#include <QWidget>

class QLabel;
class QCheckBox;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QPlainTextEdit;
class QTableWidget;
class RpcClient;

class IrcPage : public QWidget {
    Q_OBJECT
public:
    explicit IrcPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void setStatus(const QString& text, bool error = false);
    void saveConfig();
    void sendMessage();

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QCheckBox* enabledCheck_{nullptr};
    QLineEdit* serverEdit_{nullptr};
    QSpinBox* portSpin_{nullptr};
    QLineEdit* nickEdit_{nullptr};
    QLineEdit* usernameEdit_{nullptr};
    QLineEdit* realnameEdit_{nullptr};
    QLineEdit* channelEdit_{nullptr};
    QCheckBox* tlsCheck_{nullptr};
    QPlainTextEdit* messageEdit_{nullptr};
    QTableWidget* logTable_{nullptr};
    QPushButton* saveButton_{nullptr};
    QPushButton* sendButton_{nullptr};
    QPushButton* refreshButton_{nullptr};
};

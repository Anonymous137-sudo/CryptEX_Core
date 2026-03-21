#pragma once

#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QSpinBox;
class QTableWidget;
class QPushButton;
class RpcClient;

class ChatPage : public QWidget {
    Q_OBJECT
public:
    explicit ChatPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

private:
    void updateModeUi();
    void sendMessage();
    void setStatus(const QString& text, bool error = false);

    RpcClient* rpc_{nullptr};
    QLabel* infoValue_{nullptr};
    QLabel* statusValue_{nullptr};
    QTableWidget* inboxTable_{nullptr};
    QSpinBox* limitSpin_{nullptr};
    QComboBox* modeCombo_{nullptr};
    QLineEdit* peerEdit_{nullptr};
    QLineEdit* channelEdit_{nullptr};
    QLineEdit* recipientEdit_{nullptr};
    QLineEdit* recipientPubkeyEdit_{nullptr};
    QPlainTextEdit* messageEdit_{nullptr};
    QPushButton* sendButton_{nullptr};
};

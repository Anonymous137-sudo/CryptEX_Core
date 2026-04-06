#pragma once

#include <QWidget>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;
class RpcClient;

class PrivateContactsPage : public QWidget {
    Q_OBJECT
public:
    explicit PrivateContactsPage(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void refresh();

signals:
    void composePrivateMessage(const QString& address,
                               const QString& pubkeyB64,
                               const QString& peer,
                               const QString& rsaPubkeyPem);
    void startVoiceCall(const QString& address,
                        const QString& pubkeyB64,
                        const QString& peer);

private:
    void setStatus(const QString& text, bool error = false);
    void syncEditorFromSelection();
    void saveContact();
    void removeSelectedContact();
    void useSelectedContact();
    void useSelectedContactForVoice();

    RpcClient* rpc_{nullptr};
    QLabel* statusValue_{nullptr};
    QTableWidget* table_{nullptr};
    QLineEdit* labelEdit_{nullptr};
    QLineEdit* addressEdit_{nullptr};
    QLineEdit* pubkeyEdit_{nullptr};
    QPlainTextEdit* rsaPubkeyEdit_{nullptr};
    QLineEdit* peerEdit_{nullptr};
    QPlainTextEdit* notesEdit_{nullptr};
    QPushButton* saveButton_{nullptr};
    QPushButton* removeButton_{nullptr};
    QPushButton* useButton_{nullptr};
    QPushButton* voiceButton_{nullptr};
};

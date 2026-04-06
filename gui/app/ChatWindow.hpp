#pragma once

#include <QDialog>
#include <QHash>

class RpcClient;
class QTabWidget;
class ChatPage;
class VoiceCallPage;
class PrivateHistoryPage;
class ForumPage;
class PrivateContactsPage;
class PublicDirectoryPage;
class ChatProxyPage;
class IrcPage;

class ChatWindow : public QDialog {
    Q_OBJECT
public:
    explicit ChatWindow(QWidget* parent = nullptr);

    void setRpcClient(RpcClient* client);
    void showSection(const QString& key = QString());
    QString currentSection() const;
    void refreshCurrentSection();
    void composePrivateMessage(const QString& address,
                               const QString& pubkeyB64,
                               const QString& peer = QString(),
                               const QString& rsaPubkeyPem = QString());

signals:
    void sectionChanged(const QString& key);

private:
    void setSection(const QString& key, const QString& label, QWidget* page);

    QTabWidget* tabs_{nullptr};
    QHash<QString, int> indices_;
    ChatPage* publicChatPage_{nullptr};
    VoiceCallPage* voiceCallPage_{nullptr};
    ForumPage* forumPage_{nullptr};
    ChatPage* privateChatPage_{nullptr};
    PrivateHistoryPage* privateHistoryPage_{nullptr};
    PrivateContactsPage* privateContactsPage_{nullptr};
    PublicDirectoryPage* publicDirectoryPage_{nullptr};
    ChatProxyPage* proxyPage_{nullptr};
    IrcPage* ircPage_{nullptr};
};

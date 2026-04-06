#include "ChatWindow.hpp"

#include "views/ChatPage.hpp"
#include "views/VoiceCallPage.hpp"
#include "views/ForumPage.hpp"
#include "views/PrivateContactsPage.hpp"
#include "views/PrivateHistoryPage.hpp"
#include "views/PublicDirectoryPage.hpp"
#include "views/ChatProxyPage.hpp"
#include "views/IrcPage.hpp"
#include "views/ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QFrame>
#include <QScrollArea>
#include <QSizePolicy>
#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>

namespace {

QWidget* wrapMessengerPage(QWidget* page, QWidget* parent) {
    auto* scroll = new QScrollArea(parent);
    scroll->setWidget(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scroll->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContentsOnFirstShow);
    scroll->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    scroll->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    page->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    scroll->setStyleSheet(QStringLiteral("QScrollArea { background: transparent; border: none; }"));
    return scroll;
}

} // namespace

ChatWindow::ChatWindow(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(QStringLiteral("P2P Messenger"));
    resize(980, 680);
    setMinimumSize(820, 560);
    setSizeGripEnabled(true);
    chatui::applyCyberpunkTheme(this);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(6);

    tabs_ = new QTabWidget(this);
    tabs_->tabBar()->setDocumentMode(true);
    tabs_->tabBar()->setExpanding(false);
    tabs_->tabBar()->setUsesScrollButtons(true);
    root->addWidget(tabs_);

    publicChatPage_ = new ChatPage(ChatPage::ViewMode::PublicOnly, tabs_);
    voiceCallPage_ = new VoiceCallPage(tabs_);
    forumPage_ = new ForumPage(tabs_);
    privateChatPage_ = new ChatPage(ChatPage::ViewMode::PrivateOnly, tabs_);
    privateHistoryPage_ = new PrivateHistoryPage(tabs_);
    privateContactsPage_ = new PrivateContactsPage(tabs_);
    publicDirectoryPage_ = new PublicDirectoryPage(tabs_);
    proxyPage_ = new ChatProxyPage(tabs_);
    ircPage_ = new IrcPage(tabs_);

    setSection(QStringLiteral("public"), QStringLiteral("Public"), publicChatPage_);
    setSection(QStringLiteral("voice-call"), QStringLiteral("Voice Call"), voiceCallPage_);
    setSection(QStringLiteral("forum"), QStringLiteral("Forum"), forumPage_);
    setSection(QStringLiteral("private"), QStringLiteral("Private"), privateChatPage_);
    setSection(QStringLiteral("private-history"), QStringLiteral("Private History"), privateHistoryPage_);
    setSection(QStringLiteral("contacts"), QStringLiteral("Private Manager"), privateContactsPage_);
    setSection(QStringLiteral("directory"), QStringLiteral("Public Manager"), publicDirectoryPage_);
    setSection(QStringLiteral("proxy"), QStringLiteral("Tor / Proxy"), proxyPage_);
    setSection(QStringLiteral("irc"), QStringLiteral("IRC"), ircPage_);

    connect(privateContactsPage_, &PrivateContactsPage::composePrivateMessage,
            this, [this](const QString& address, const QString& pubkey, const QString& peer, const QString& rsaPubkeyPem) {
                composePrivateMessage(address, pubkey, peer, rsaPubkeyPem);
            });
    connect(privateContactsPage_, &PrivateContactsPage::startVoiceCall,
            this, [this](const QString& address, const QString& pubkey, const QString& peer) {
                voiceCallPage_->setCallTarget(address, pubkey, peer);
                showSection(QStringLiteral("voice-call"));
                voiceCallPage_->refresh();
            });
    connect(forumPage_, &ForumPage::commentRequested,
            this, [this](const QString& channel, const QString& draft) {
                publicChatPage_->setPublicDraft(channel, draft);
                showSection(QStringLiteral("public"));
            });
    connect(privateHistoryPage_, &PrivateHistoryPage::replyRequested,
            this, [this](const QString& address, const QString& pubkey, const QString& peer, const QString& draft) {
                privateChatPage_->setPrivateRecipient(address, pubkey, peer, draft);
                showSection(QStringLiteral("private"));
            });
    connect(publicDirectoryPage_, &PublicDirectoryPage::messageRequested,
            this, [this](const QString& address, const QString& pubkey, const QString& peer) {
                composePrivateMessage(address, pubkey, peer, QString());
            });
    connect(publicDirectoryPage_, &PublicDirectoryPage::callRequested,
            this, [this](const QString& address, const QString& pubkey, const QString& peer) {
                voiceCallPage_->setCallTarget(address, pubkey, peer);
                showSection(QStringLiteral("voice-call"));
                voiceCallPage_->refresh();
            });
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int) {
        refreshCurrentSection();
        emit sectionChanged(currentSection());
    });
}

void ChatWindow::setRpcClient(RpcClient* client) {
    publicChatPage_->setRpcClient(client);
    voiceCallPage_->setRpcClient(client);
    forumPage_->setRpcClient(client);
    privateChatPage_->setRpcClient(client);
    privateHistoryPage_->setRpcClient(client);
    privateContactsPage_->setRpcClient(client);
    publicDirectoryPage_->setRpcClient(client);
    proxyPage_->setRpcClient(client);
    ircPage_->setRpcClient(client);
}

void ChatWindow::setSection(const QString& key, const QString& label, QWidget* page) {
    if (!tabs_ || !page) return;
    page->setParent(tabs_);
    indices_.insert(key, tabs_->addTab(wrapMessengerPage(page, tabs_), label));
}

void ChatWindow::showSection(const QString& key) {
    bool changedTab = false;
    if (!key.isEmpty() && indices_.contains(key)) {
        const int targetIndex = indices_.value(key);
        changedTab = tabs_->currentIndex() != targetIndex;
        tabs_->setCurrentIndex(targetIndex);
    }
    if (!changedTab) {
        refreshCurrentSection();
    }
    show();
    raise();
    activateWindow();
}

QString ChatWindow::currentSection() const {
    if (!tabs_) return {};
    const int current = tabs_->currentIndex();
    for (auto it = indices_.cbegin(); it != indices_.cend(); ++it) {
        if (it.value() == current) return it.key();
    }
    return {};
}

void ChatWindow::refreshCurrentSection() {
    const auto section = currentSection();
    if (section == QStringLiteral("public")) {
        publicChatPage_->refresh();
    } else if (section == QStringLiteral("voice-call")) {
        voiceCallPage_->refresh();
    } else if (section == QStringLiteral("forum")) {
        forumPage_->refresh();
    } else if (section == QStringLiteral("private")) {
        privateChatPage_->refresh();
    } else if (section == QStringLiteral("private-history")) {
        privateHistoryPage_->refresh();
    } else if (section == QStringLiteral("contacts")) {
        privateContactsPage_->refresh();
    } else if (section == QStringLiteral("directory")) {
        publicDirectoryPage_->refresh();
    } else if (section == QStringLiteral("proxy")) {
        proxyPage_->refresh();
    } else if (section == QStringLiteral("irc")) {
        ircPage_->refresh();
    }
}

void ChatWindow::composePrivateMessage(const QString& address,
                                       const QString& pubkeyB64,
                                       const QString& peer,
                                       const QString& rsaPubkeyPem) {
    privateChatPage_->setPrivateRecipient(address, pubkeyB64, peer, QString(), rsaPubkeyPem);
    showSection(QStringLiteral("private"));
    privateChatPage_->refresh();
}

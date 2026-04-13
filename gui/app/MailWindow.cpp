#include "MailWindow.hpp"

#include "views/ChatTheme.hpp"
#include "views/MailAccountCreatePage.hpp"
#include "views/MailAccountsPage.hpp"
#include "views/MailComposePage.hpp"
#include "views/MailListPage.hpp"
#include "views/MailSecurityPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>

MailWindow::MailWindow(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(QStringLiteral("P2P Mail Service"));
    resize(1060, 720);
    setMinimumSize(900, 620);
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

    composePage_ = new MailComposePage(tabs_);
    inboxPage_ = new MailListPage(MailListPage::Folder::Inbox, tabs_);
    sentPage_ = new MailListPage(MailListPage::Folder::Sent, tabs_);
    createAccountPage_ = new MailAccountCreatePage(tabs_);
    accountsPage_ = new MailAccountsPage(tabs_);
    securityPage_ = new MailSecurityPage(tabs_);

    setSection(QStringLiteral("compose"), QStringLiteral("Compose Mail"), composePage_);
    setSection(QStringLiteral("inbox"), QStringLiteral("Inbox"), inboxPage_);
    setSection(QStringLiteral("sent"), QStringLiteral("Sent"), sentPage_);
    setSection(QStringLiteral("create"), QStringLiteral("Create Account"), createAccountPage_);
    setSection(QStringLiteral("accounts"), QStringLiteral("Accounts"), accountsPage_);
    setSection(QStringLiteral("security"), QStringLiteral("Privacy"), securityPage_);

    connect(inboxPage_, &MailListPage::replyRequested, this, [this](const QString& to, const QString& subject, const QString& body) {
        composeMail(to, subject, body);
    });
    connect(sentPage_, &MailListPage::replyRequested, this, [this](const QString& to, const QString& subject, const QString& body) {
        composeMail(to, subject, body);
    });
    connect(composePage_, &MailComposePage::mailSent, this, [this]() {
        showSection(QStringLiteral("sent"));
        sentPage_->refresh();
    });
    connect(createAccountPage_, &MailAccountCreatePage::accountCreated, this, [this]() {
        composePage_->refresh();
        accountsPage_->refresh();
        inboxPage_->refresh();
        sentPage_->refresh();
        showSection(QStringLiteral("accounts"));
    });
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int) {
        refreshCurrentSection();
        emit sectionChanged(currentSection());
    });
}

void MailWindow::setRpcClient(RpcClient* client) {
    inboxPage_->setRpcClient(client);
    sentPage_->setRpcClient(client);
    composePage_->setRpcClient(client);
    createAccountPage_->setRpcClient(client);
    accountsPage_->setRpcClient(client);
    securityPage_->setRpcClient(client);
}

void MailWindow::setSection(const QString& key, const QString& label, QWidget* page) {
    page->setParent(tabs_);
    indices_.insert(key, tabs_->addTab(page, label));
}

void MailWindow::showSection(const QString& key) {
    bool changedTab = false;
    if (!key.isEmpty() && indices_.contains(key)) {
        const int idx = indices_.value(key);
        changedTab = tabs_->currentIndex() != idx;
        tabs_->setCurrentIndex(idx);
    }
    if (!changedTab) {
        refreshCurrentSection();
    }
    show();
    raise();
    activateWindow();
}

QString MailWindow::currentSection() const {
    const int current = tabs_ ? tabs_->currentIndex() : -1;
    for (auto it = indices_.cbegin(); it != indices_.cend(); ++it) {
        if (it.value() == current) return it.key();
    }
    return {};
}

void MailWindow::refreshCurrentSection() {
    const auto section = currentSection();
    if (section == QStringLiteral("inbox")) {
        inboxPage_->refresh();
    } else if (section == QStringLiteral("sent")) {
        sentPage_->refresh();
    } else if (section == QStringLiteral("compose")) {
        composePage_->refresh();
    } else if (section == QStringLiteral("create")) {
        createAccountPage_->refresh();
    } else if (section == QStringLiteral("accounts")) {
        accountsPage_->refresh();
    } else if (section == QStringLiteral("security")) {
        securityPage_->refresh();
    }
}

void MailWindow::composeMail(const QString& toMailAddress, const QString& subject, const QString& body) {
    composePage_->setDraft(toMailAddress, subject, body);
    showSection(QStringLiteral("compose"));
}

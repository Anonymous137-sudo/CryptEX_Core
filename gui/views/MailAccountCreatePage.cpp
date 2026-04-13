#include "MailAccountCreatePage.hpp"

#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QCheckBox>
#include <QGuiApplication>
#include <QClipboard>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

MailAccountCreatePage::MailAccountCreatePage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Create Mail Account"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* intro = new QLabel(QStringLiteral("Create a new wallet-backed mail identity. Each identity becomes a decentralized alias in the form wallet_address@p2pmail.crx."), this);
    intro->setWordWrap(true);
    root->addWidget(intro);

    auto* formBox = new QGroupBox(QStringLiteral("Account Creation"), this);
    auto* form = new QFormLayout(formBox);
    labelEdit_ = new QLineEdit(formBox);
    labelEdit_->setPlaceholderText(QStringLiteral("Optional label, e.g. Ops Mail"));
    setPrimaryCheck_ = new QCheckBox(QStringLiteral("Make this the primary wallet/mail address"), formBox);
    aliasValue_ = new QLabel(QStringLiteral("No mail identity created in this session yet."), formBox);
    aliasValue_->setWordWrap(true);
    form->addRow(QStringLiteral("Label"), labelEdit_);
    form->addRow(QString(), setPrimaryCheck_);
    form->addRow(QStringLiteral("Created Alias"), aliasValue_);
    root->addWidget(formBox);

    auto* buttons = new QHBoxLayout();
    createButton_ = new QPushButton(QStringLiteral("Create Mail Identity"), this);
    createButton_->setObjectName(QStringLiteral("forumAccentButton"));
    copyButton_ = new QPushButton(QStringLiteral("Copy Alias"), this);
    buttons->addWidget(createButton_);
    buttons->addWidget(copyButton_);
    buttons->addStretch(1);
    root->addLayout(buttons);

    statusValue_ = new QLabel(QStringLiteral("Ready."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);
    root->addStretch(1);

    connect(createButton_, &QPushButton::clicked, this, [this]() { createAccount(); });
    connect(copyButton_, &QPushButton::clicked, this, [this]() { copyAlias(); });
}

void MailAccountCreatePage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void MailAccountCreatePage::refresh() {
    if (aliasValue_->text().trimmed().isEmpty()) {
        aliasValue_->setText(QStringLiteral("No mail identity created in this session yet."));
    }
}

void MailAccountCreatePage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void MailAccountCreatePage::createAccount() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    createButton_->setEnabled(false);
    rpc_->call(QStringLiteral("getnewaddress"), QJsonArray{}, this,
        [this](const QJsonValue& result) {
            const QString address = result.toString().trimmed();
            if (address.isEmpty()) {
                createButton_->setEnabled(true);
                setStatus(QStringLiteral("Backend returned an empty wallet address."), true);
                return;
            }
            const QString alias = address + QStringLiteral("@p2pmail.crx");
            auto finalize = [this, alias]() {
                aliasValue_->setText(alias);
                createButton_->setEnabled(true);
                setStatus(QStringLiteral("Created new mail identity: %1").arg(alias));
                emit accountCreated();
            };
            const QString label = labelEdit_->text().trimmed();
            const bool setPrimary = setPrimaryCheck_->isChecked();
            if (!label.isEmpty()) {
                rpc_->call(QStringLiteral("setaddresslabel"), QJsonArray{address, label}, this,
                    [this, address, setPrimary, finalize](const QJsonValue&) {
                        if (setPrimary) {
                            rpc_->call(QStringLiteral("setprimaryaddress"), QJsonArray{address}, this,
                                [finalize](const QJsonValue&) { finalize(); },
                                [this, finalize](const QString& error) {
                                    finalize();
                                    setStatus(QStringLiteral("Mail identity created, but setting it primary failed: %1").arg(error), true);
                                });
                        } else {
                            finalize();
                        }
                    },
                    [this, address, setPrimary, finalize](const QString& error) {
                        if (setPrimary) {
                            rpc_->call(QStringLiteral("setprimaryaddress"), QJsonArray{address}, this,
                                [finalize](const QJsonValue&) { finalize(); },
                                [this, error](const QString& primaryError) {
                                    createButton_->setEnabled(true);
                                    setStatus(QStringLiteral("Mail identity created, but label and primary update failed: %1 | %2").arg(error, primaryError), true);
                                });
                        } else {
                            finalize();
                            setStatus(QStringLiteral("Mail identity created, but label update failed: %1").arg(error), true);
                        }
                    });
            } else if (setPrimary) {
                rpc_->call(QStringLiteral("setprimaryaddress"), QJsonArray{address}, this,
                    [finalize](const QJsonValue&) { finalize(); },
                    [this, finalize](const QString& error) {
                        finalize();
                        setStatus(QStringLiteral("Mail identity created, but setting it primary failed: %1").arg(error), true);
                    });
            } else {
                finalize();
            }
        },
        [this](const QString& error) {
            createButton_->setEnabled(true);
            setStatus(QStringLiteral("Unable to create mail identity: %1").arg(error), true);
        });
}

void MailAccountCreatePage::copyAlias() {
    const QString alias = aliasValue_->text().trimmed();
    if (alias.isEmpty() || alias.startsWith(QStringLiteral("No mail identity"))) {
        setStatus(QStringLiteral("Create a mail identity first."), true);
        return;
    }
    QGuiApplication::clipboard()->setText(alias);
    setStatus(QStringLiteral("Copied %1").arg(alias));
}

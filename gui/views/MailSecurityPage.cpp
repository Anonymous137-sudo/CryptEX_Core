#include "MailSecurityPage.hpp"

#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QCheckBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

MailSecurityPage::MailSecurityPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Mail Privacy / Security"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Distributed mailbox, Tor/SOCKS5 routing, and mail 2FA controls."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* storeBox = new QGroupBox(QStringLiteral("Distributed Mailbox"), this);
    auto* storeLayout = new QFormLayout(storeBox);
    distributedStoreValue_ = new QLabel(QStringLiteral("Loading distributed store status..."), storeBox);
    distributedStoreValue_->setWordWrap(true);
    storeLayout->addRow(QStringLiteral("Store"), distributedStoreValue_);
    root->addWidget(storeBox);

    auto* proxyBox = new QGroupBox(QStringLiteral("Tor / SOCKS5 Proxy"), this);
    auto* proxyLayout = new QFormLayout(proxyBox);
    proxyEnabledCheck_ = new QCheckBox(QStringLiteral("Enable SOCKS5 proxy for P2P mail routing"), proxyBox);
    proxyHostEdit_ = new QLineEdit(proxyBox);
    proxyPortSpin_ = new QSpinBox(proxyBox);
    proxyPortSpin_->setRange(1, 65535);
    proxyPortSpin_->setValue(9050);
    proxyRemoteDnsCheck_ = new QCheckBox(QStringLiteral("Resolve DNS through proxy"), proxyBox);
    proxyRemoteDnsCheck_->setChecked(true);
    proxyLayout->addRow(QString(), proxyEnabledCheck_);
    proxyLayout->addRow(QStringLiteral("Proxy Host"), proxyHostEdit_);
    proxyLayout->addRow(QStringLiteral("Proxy Port"), proxyPortSpin_);
    proxyLayout->addRow(QString(), proxyRemoteDnsCheck_);

    auto* proxyButtons = new QHBoxLayout();
    proxyReloadButton_ = new QPushButton(QStringLiteral("Reload Proxy"), proxyBox);
    proxySaveButton_ = new QPushButton(QStringLiteral("Save Proxy"), proxyBox);
    proxyButtons->addWidget(proxyReloadButton_);
    proxyButtons->addStretch(1);
    proxyButtons->addWidget(proxySaveButton_);
    proxyLayout->addRow(QString(), proxyButtons);
    root->addWidget(proxyBox);

    auto* authBox = new QGroupBox(QStringLiteral("Mail 2FA"), this);
    auto* authLayout = new QFormLayout(authBox);
    twoFactorEnabledCheck_ = new QCheckBox(QStringLiteral("Require TOTP code for sending and deleting mail"), authBox);
    issuerEdit_ = new QLineEdit(authBox);
    issuerEdit_->setPlaceholderText(QStringLiteral("CryptEX P2P Mail"));
    secretEdit_ = new QLineEdit(authBox);
    secretEdit_->setReadOnly(true);
    otpAuthUriEdit_ = new QLineEdit(authBox);
    otpAuthUriEdit_->setReadOnly(true);
    verifyCodeEdit_ = new QLineEdit(authBox);
    verifyCodeEdit_->setPlaceholderText(QStringLiteral("6-digit code"));
    verifyCodeEdit_->setMaxLength(6);
    authLayout->addRow(QString(), twoFactorEnabledCheck_);
    authLayout->addRow(QStringLiteral("Issuer"), issuerEdit_);
    authLayout->addRow(QStringLiteral("Secret"), secretEdit_);
    authLayout->addRow(QStringLiteral("OTPAuth URI"), otpAuthUriEdit_);
    authLayout->addRow(QStringLiteral("Verify Code"), verifyCodeEdit_);

    auto* authButtons = new QHBoxLayout();
    regenerateButton_ = new QPushButton(QStringLiteral("Regenerate Secret"), authBox);
    verifyButton_ = new QPushButton(QStringLiteral("Verify"), authBox);
    saveTwoFactorButton_ = new QPushButton(QStringLiteral("Save 2FA"), authBox);
    authButtons->addWidget(regenerateButton_);
    authButtons->addWidget(verifyButton_);
    authButtons->addStretch(1);
    authButtons->addWidget(saveTwoFactorButton_);
    authLayout->addRow(QString(), authButtons);
    root->addWidget(authBox);

    auto* policyBox = new QGroupBox(QStringLiteral("Mailbox Replication Policy"), this);
    auto* policyLayout = new QFormLayout(policyBox);
    ttlHoursSpin_ = new QSpinBox(policyBox);
    ttlHoursSpin_->setRange(1, 24 * 365);
    ttlHoursSpin_->setValue(168);
    replicaTargetSpin_ = new QSpinBox(policyBox);
    replicaTargetSpin_->setRange(1, 64);
    replicaTargetSpin_->setValue(3);
    maxStoreItemsSpin_ = new QSpinBox(policyBox);
    maxStoreItemsSpin_->setRange(1, 1000000);
    maxStoreItemsSpin_->setValue(5000);
    pruneImportedCheck_ = new QCheckBox(QStringLiteral("Prune distributed copy after local import"), policyBox);
    pruneExpiredCheck_ = new QCheckBox(QStringLiteral("Prune expired mail from distributed store"), policyBox);
    pruneExpiredCheck_->setChecked(true);
    proofOfStorageCheck_ = new QCheckBox(QStringLiteral("Require proof-of-storage receipts and challenges"), policyBox);
    proofOfStorageCheck_->setChecked(true);
    challengeIntervalSpin_ = new QSpinBox(policyBox);
    challengeIntervalSpin_->setRange(1, 24 * 60);
    challengeIntervalSpin_->setValue(30);
    minimumBondEdit_ = new QLineEdit(policyBox);
    minimumBondEdit_->setPlaceholderText(QStringLiteral("0"));
    requiredVerifiedReplicasSpin_ = new QSpinBox(policyBox);
    requiredVerifiedReplicasSpin_->setRange(1, 64);
    requiredVerifiedReplicasSpin_->setValue(1);
    slashOnFailedProofCheck_ = new QCheckBox(QStringLiteral("Slash failed or invalid storage proofs"), policyBox);
    slashOnFailedProofCheck_->setChecked(true);
    slashPenaltySpin_ = new QSpinBox(policyBox);
    slashPenaltySpin_->setRange(1, 1000);
    slashPenaltySpin_->setValue(25);
    natAssistCheck_ = new QCheckBox(QStringLiteral("Enable NAT assist and hole-punch hints"), policyBox);
    natAssistCheck_->setChecked(true);
    relayFallbackCheck_ = new QCheckBox(QStringLiteral("Allow relay fallback when direct mail routing is unavailable"), policyBox);
    relayFallbackCheck_->setChecked(true);
    relayPeersEdit_ = new QLineEdit(policyBox);
    relayPeersEdit_->setPlaceholderText(QStringLiteral("Optional dedicated relay peers, comma-separated"));
    stunServersEdit_ = new QLineEdit(policyBox);
    stunServersEdit_->setPlaceholderText(QStringLiteral("STUN servers like stun.example.org:3478, comma-separated"));
    stunTimeoutSpin_ = new QSpinBox(policyBox);
    stunTimeoutSpin_->setRange(100, 10000);
    stunTimeoutSpin_->setSingleStep(100);
    stunTimeoutSpin_->setValue(1200);
    savePolicyButton_ = new QPushButton(QStringLiteral("Save Mail Policy"), policyBox);
    policyLayout->addRow(QStringLiteral("TTL (hours)"), ttlHoursSpin_);
    policyLayout->addRow(QStringLiteral("Replica Target"), replicaTargetSpin_);
    policyLayout->addRow(QStringLiteral("Max Store Items"), maxStoreItemsSpin_);
    policyLayout->addRow(QString(), pruneImportedCheck_);
    policyLayout->addRow(QString(), pruneExpiredCheck_);
    policyLayout->addRow(QString(), proofOfStorageCheck_);
    policyLayout->addRow(QStringLiteral("Proof Challenge (minutes)"), challengeIntervalSpin_);
    policyLayout->addRow(QStringLiteral("Minimum Bond (sats)"), minimumBondEdit_);
    policyLayout->addRow(QStringLiteral("Trusted Verified Replicas"), requiredVerifiedReplicasSpin_);
    policyLayout->addRow(QString(), slashOnFailedProofCheck_);
    policyLayout->addRow(QStringLiteral("Slash Penalty Score"), slashPenaltySpin_);
    policyLayout->addRow(QString(), natAssistCheck_);
    policyLayout->addRow(QString(), relayFallbackCheck_);
    policyLayout->addRow(QStringLiteral("Dedicated Relay Peers"), relayPeersEdit_);
    policyLayout->addRow(QStringLiteral("STUN Servers"), stunServersEdit_);
    policyLayout->addRow(QStringLiteral("STUN Timeout (ms)"), stunTimeoutSpin_);
    policyLayout->addRow(QString(), savePolicyButton_);
    root->addWidget(policyBox);
    root->addStretch(1);

    connect(proxyReloadButton_, &QPushButton::clicked, this, [this]() { refresh(); });
    connect(proxySaveButton_, &QPushButton::clicked, this, [this]() { saveProxy(); });
    connect(regenerateButton_, &QPushButton::clicked, this, [this]() { saveTwoFactor(); });
    connect(verifyButton_, &QPushButton::clicked, this, [this]() { verifyTwoFactor(); });
    connect(saveTwoFactorButton_, &QPushButton::clicked, this, [this]() { saveTwoFactor(); });
    connect(savePolicyButton_, &QPushButton::clicked, this, [this]() {
        if (!rpc_) return;
        bool bondOk = false;
        const auto minimumBond = minimumBondEdit_->text().trimmed().toULongLong(&bondOk);
        if (!bondOk && !minimumBondEdit_->text().trimmed().isEmpty()) {
            setStatus(QStringLiteral("Minimum bond must be a non-negative integer amount in satoshis."), true);
            return;
        }
        QJsonObject object;
        object.insert(QStringLiteral("ttl_hours"), ttlHoursSpin_->value());
        object.insert(QStringLiteral("replica_target"), replicaTargetSpin_->value());
        object.insert(QStringLiteral("max_store_items"), maxStoreItemsSpin_->value());
        object.insert(QStringLiteral("prune_imported"), pruneImportedCheck_->isChecked());
        object.insert(QStringLiteral("prune_expired"), pruneExpiredCheck_->isChecked());
        object.insert(QStringLiteral("proof_of_storage"), proofOfStorageCheck_->isChecked());
        object.insert(QStringLiteral("challenge_interval_minutes"), challengeIntervalSpin_->value());
        object.insert(QStringLiteral("minimum_bond_sats"), static_cast<qint64>(minimumBond));
        object.insert(QStringLiteral("required_verified_replicas"), requiredVerifiedReplicasSpin_->value());
        object.insert(QStringLiteral("slash_on_failed_proof"), slashOnFailedProofCheck_->isChecked());
        object.insert(QStringLiteral("slash_penalty_score"), slashPenaltySpin_->value());
        object.insert(QStringLiteral("nat_assist"), natAssistCheck_->isChecked());
        object.insert(QStringLiteral("relay_fallback"), relayFallbackCheck_->isChecked());
        {
            QJsonArray relays;
            for (const auto& relay : relayPeersEdit_->text().split(',', Qt::SkipEmptyParts)) {
                const auto trimmed = relay.trimmed();
                if (!trimmed.isEmpty()) relays.append(trimmed);
            }
            object.insert(QStringLiteral("relay_peers"), relays);
        }
        {
            QJsonArray servers;
            for (const auto& server : stunServersEdit_->text().split(',', Qt::SkipEmptyParts)) {
                const auto trimmed = server.trimmed();
                if (!trimmed.isEmpty()) servers.append(trimmed);
            }
            object.insert(QStringLiteral("stun_servers"), servers);
        }
        object.insert(QStringLiteral("stun_timeout_ms"), stunTimeoutSpin_->value());
        rpc_->call(QStringLiteral("setp2pmailpolicy"), QJsonArray{object}, this,
            [this](const QJsonValue& result) {
                const auto obj = result.toObject();
                setStatus(QStringLiteral("Mail policy saved. Pruned %1 stale item(s).")
                              .arg(obj.value(QStringLiteral("pruned")).toInteger()));
                refresh();
            },
            [this](const QString& error) {
                setStatus(QStringLiteral("Unable to save mail policy: %1").arg(error), true);
            });
    });
}

void MailSecurityPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void MailSecurityPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void MailSecurityPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    rpc_->call(QStringLiteral("getp2pmailproxyconfig"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            proxyEnabledCheck_->setChecked(obj.value(QStringLiteral("enabled")).toBool(false));
            proxyHostEdit_->setText(obj.value(QStringLiteral("host")).toString());
            proxyPortSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("port")).toInteger(9050)));
            proxyRemoteDnsCheck_->setChecked(obj.value(QStringLiteral("remote_dns")).toBool(true));
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Proxy settings unavailable: %1").arg(error), true);
        });

    rpc_->call(QStringLiteral("getp2pmailsecurity"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            distributedStoreValue_->setText(QStringLiteral("%1 replicated mail item(s) stored locally\n%2\nDHT peers: %3 | pending queries: %4 | seen queries: %5\nReceipts: %6 | verified: %7 | bond-satisfied: %8 | trusted verified: %9 | slashed: %10 | pending proofs: %11\nMinimum bond: %12 sats | required trusted replicas: %13 | slash proofs: %18 | slash penalty: %19\nNAT assist: %14 | relay fallback: %15 | candidates: %16 | advertised endpoint: %17\nReflexive endpoint: %20 | STUN servers: %21 | relay peers: %22 | port mapping: %23")
                                                .arg(obj.value(QStringLiteral("distributed_store_count")).toInteger())
                                                .arg(obj.value(QStringLiteral("distributed_store_path")).toString())
                                                .arg(obj.value(QStringLiteral("dht_active_peers")).toInteger())
                                                .arg(obj.value(QStringLiteral("dht_pending_queries")).toInteger())
                                                .arg(obj.value(QStringLiteral("dht_seen_queries")).toInteger())
                                                .arg(obj.value(QStringLiteral("proof_receipts")).toInteger())
                                                .arg(obj.value(QStringLiteral("verified_receipts")).toInteger())
                                                .arg(obj.value(QStringLiteral("bond_satisfied_receipts")).toInteger())
                                                .arg(obj.value(QStringLiteral("trusted_verified_receipts")).toInteger())
                                                .arg(obj.value(QStringLiteral("slashed_receipts")).toInteger())
                                                .arg(obj.value(QStringLiteral("pending_proofs")).toInteger())
                                                .arg(obj.value(QStringLiteral("minimum_bond_sats")).toVariant().toString())
                                                .arg(obj.value(QStringLiteral("required_verified_replicas")).toInteger())
                                                .arg(obj.value(QStringLiteral("nat_assist")).toBool() ? QStringLiteral("on") : QStringLiteral("off"))
                                                .arg(obj.value(QStringLiteral("relay_fallback")).toBool() ? QStringLiteral("on") : QStringLiteral("off"))
                                                .arg(obj.value(QStringLiteral("candidate_count")).toInteger())
                                                .arg(obj.value(QStringLiteral("advertised_endpoint")).toString(QStringLiteral("unavailable")))
                                                .arg(obj.value(QStringLiteral("slash_on_failed_proof")).toBool() ? QStringLiteral("on") : QStringLiteral("off"))
                                                .arg(obj.value(QStringLiteral("slash_penalty_score")).toInteger())
                                                .arg(obj.value(QStringLiteral("reflexive_endpoint")).toString(QStringLiteral("unavailable")))
                                                .arg(obj.value(QStringLiteral("stun_server_count")).toInteger())
                                                .arg(obj.value(QStringLiteral("relay_peer_count")).toInteger())
                                                .arg(obj.value(QStringLiteral("port_mapping_active")).toBool() ? QStringLiteral("active") : QStringLiteral("inactive")));
            twoFactorEnabledCheck_->setChecked(obj.value(QStringLiteral("two_factor_enabled")).toBool(false));
            issuerEdit_->setText(obj.value(QStringLiteral("issuer")).toString());
            secretEdit_->setText(obj.value(QStringLiteral("totp_secret_b32")).toString());
            otpAuthUriEdit_->setText(obj.value(QStringLiteral("otpauth_uri")).toString());
            setStatus(QStringLiteral("Loaded mail privacy and 2FA settings."));
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Mail security unavailable: %1").arg(error), true);
        });

    rpc_->call(QStringLiteral("getp2pmailpolicy"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            ttlHoursSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("ttl_hours")).toInteger(168)));
            replicaTargetSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("replica_target")).toInteger(3)));
            maxStoreItemsSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("max_store_items")).toInteger(5000)));
            pruneImportedCheck_->setChecked(obj.value(QStringLiteral("prune_imported")).toBool(false));
            pruneExpiredCheck_->setChecked(obj.value(QStringLiteral("prune_expired")).toBool(true));
            proofOfStorageCheck_->setChecked(obj.value(QStringLiteral("proof_of_storage")).toBool(true));
            challengeIntervalSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("challenge_interval_minutes")).toInteger(30)));
            minimumBondEdit_->setText(obj.value(QStringLiteral("minimum_bond_sats")).toVariant().toString());
            requiredVerifiedReplicasSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("required_verified_replicas")).toInteger(1)));
            slashOnFailedProofCheck_->setChecked(obj.value(QStringLiteral("slash_on_failed_proof")).toBool(true));
            slashPenaltySpin_->setValue(static_cast<int>(obj.value(QStringLiteral("slash_penalty_score")).toInteger(25)));
            natAssistCheck_->setChecked(obj.value(QStringLiteral("nat_assist")).toBool(true));
            relayFallbackCheck_->setChecked(obj.value(QStringLiteral("relay_fallback")).toBool(true));
            const auto relays = obj.value(QStringLiteral("relay_peers")).toArray();
            QStringList relayList;
            for (const auto& relay : relays) relayList << relay.toString();
            relayPeersEdit_->setText(relayList.join(QStringLiteral(", ")));
            const auto stunServers = obj.value(QStringLiteral("stun_servers")).toArray();
            QStringList stunList;
            for (const auto& server : stunServers) stunList << server.toString();
            stunServersEdit_->setText(stunList.join(QStringLiteral(", ")));
            stunTimeoutSpin_->setValue(static_cast<int>(obj.value(QStringLiteral("stun_timeout_ms")).toInteger(1200)));
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Mail policy unavailable: %1").arg(error), true);
        });
}

void MailSecurityPage::saveProxy() {
    if (!rpc_) return;
    QJsonObject object;
    object.insert(QStringLiteral("enabled"), proxyEnabledCheck_->isChecked());
    object.insert(QStringLiteral("host"), proxyHostEdit_->text().trimmed());
    object.insert(QStringLiteral("port"), proxyPortSpin_->value());
    object.insert(QStringLiteral("remote_dns"), proxyRemoteDnsCheck_->isChecked());
    rpc_->call(QStringLiteral("setp2pmailproxyconfig"), QJsonArray{object}, this,
        [this](const QJsonValue&) {
            setStatus(QStringLiteral("Mail proxy configuration saved."));
            refresh();
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to save mail proxy: %1").arg(error), true);
        });
}

void MailSecurityPage::saveTwoFactor() {
    if (!rpc_) return;
    QJsonObject object;
    object.insert(QStringLiteral("two_factor_enabled"), twoFactorEnabledCheck_->isChecked());
    object.insert(QStringLiteral("issuer"), issuerEdit_->text().trimmed());
    if (!secretEdit_->text().trimmed().isEmpty()) {
        object.insert(QStringLiteral("totp_secret_b32"), secretEdit_->text().trimmed());
    }
    if (sender() == regenerateButton_) {
        object.insert(QStringLiteral("regenerate_secret"), true);
    }
    rpc_->call(QStringLiteral("setp2pmailsecurity"), QJsonArray{object}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            secretEdit_->setText(obj.value(QStringLiteral("totp_secret_b32")).toString());
            otpAuthUriEdit_->setText(obj.value(QStringLiteral("otpauth_uri")).toString());
            issuerEdit_->setText(obj.value(QStringLiteral("issuer")).toString());
            twoFactorEnabledCheck_->setChecked(obj.value(QStringLiteral("two_factor_enabled")).toBool(false));
            setStatus(QStringLiteral("Mail 2FA settings saved."));
            refresh();
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to save mail 2FA: %1").arg(error), true);
        });
}

void MailSecurityPage::verifyTwoFactor() {
    if (!rpc_) return;
    const QString code = verifyCodeEdit_->text().trimmed();
    if (code.isEmpty()) {
        setStatus(QStringLiteral("Enter a 6-digit code to verify the mail 2FA secret."), true);
        return;
    }
    rpc_->call(QStringLiteral("verifyp2pmail2fa"), QJsonArray{code}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            setStatus(obj.value(QStringLiteral("verified")).toBool(false)
                          ? QStringLiteral("Mail 2FA code verified.")
                          : QStringLiteral("Mail 2FA code did not verify."),
                      !obj.value(QStringLiteral("verified")).toBool(false));
        },
        [this](const QString& error) {
            setStatus(QStringLiteral("Unable to verify mail 2FA: %1").arg(error), true);
        });
}

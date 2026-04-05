#include "DashboardPage.hpp"
#include "rpc/RpcClient.hpp"

#include <algorithm>
#include <QBoxLayout>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QListWidget>
#include <QVBoxLayout>

namespace {

QLabel* makeValueLabel() {
    auto* label = new QLabel(QStringLiteral("-"));
    label->setObjectName(QStringLiteral("valueLabel"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setWordWrap(true);
    return label;
}

QFrame* makePanelFrame(QWidget* parent) {
    auto* frame = new QFrame(parent);
    frame->setObjectName(QStringLiteral("panelFrame"));
    return frame;
}

QLabel* makePanelHeader(const QString& text, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setObjectName(QStringLiteral("panelHeader"));
    return label;
}

} // namespace

DashboardPage::DashboardPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    topRowLayout_ = new QBoxLayout(QBoxLayout::LeftToRight);
    topRowLayout_->setSpacing(12);

    auto* balancesFrame = makePanelFrame(this);
    auto* balancesLayout = new QVBoxLayout(balancesFrame);
    balancesLayout->setContentsMargins(14, 14, 14, 14);
    balancesLayout->setSpacing(14);
    balancesLayout->addWidget(makePanelHeader(QStringLiteral("Balances"), balancesFrame));

    auto* balancesForm = new QFormLayout();
    balancesForm->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    balancesForm->setHorizontalSpacing(24);
    balancesForm->setVerticalSpacing(12);
    availableValue_ = makeValueLabel();
    pendingValue_ = makeValueLabel();
    lockedValue_ = makeValueLabel();
    totalValue_ = makeValueLabel();
    approvalValue_ = makeValueLabel();
    balancesForm->addRow(QStringLiteral("Available:"), availableValue_);
    balancesForm->addRow(QStringLiteral("Pending:"), pendingValue_);
    balancesForm->addRow(QStringLiteral("Locked:"), lockedValue_);
    balancesForm->addRow(QStringLiteral("Total:"), totalValue_);
    balancesForm->addRow(QStringLiteral("Chain approval:"), approvalValue_);
    balancesLayout->addLayout(balancesForm);
    balancesLayout->addStretch(1);
    topRowLayout_->addWidget(balancesFrame, 1);

    auto* txFrame = makePanelFrame(this);
    auto* txLayout = new QVBoxLayout(txFrame);
    txLayout->setContentsMargins(14, 14, 14, 14);
    txLayout->setSpacing(12);
    txLayout->addWidget(makePanelHeader(QStringLiteral("Recent transactions"), txFrame));
    recentTransactions_ = new QListWidget(txFrame);
    recentTransactions_->setSelectionMode(QAbstractItemView::NoSelection);
    recentTransactions_->setFocusPolicy(Qt::NoFocus);
    recentTransactions_->setAlternatingRowColors(false);
    recentTransactions_->addItem(QStringLiteral("No transactions yet."));
    txLayout->addWidget(recentTransactions_, 1);
    topRowLayout_->addWidget(txFrame, 1);

    root->addLayout(topRowLayout_, 1);

    auto* chainFrame = makePanelFrame(this);
    auto* chainLayout = new QVBoxLayout(chainFrame);
    chainLayout->setContentsMargins(14, 14, 14, 14);
    chainLayout->setSpacing(12);
    chainLayout->addWidget(makePanelHeader(QStringLiteral("Node status"), chainFrame));

    auto* form = new QFormLayout();
    form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    form->setHorizontalSpacing(24);
    form->setVerticalSpacing(10);
    networkValue_ = makeValueLabel();
    blocksValue_ = makeValueLabel();
    bestHashValue_ = makeValueLabel();
    connectionsValue_ = makeValueLabel();
    validatedPeersValue_ = makeValueLabel();
    peersValue_ = makeValueLabel();
    difficultyValue_ = makeValueLabel();
    mempoolValue_ = makeValueLabel();
    endpointValue_ = makeValueLabel();
    hashrateValue_ = makeValueLabel();
    syncValue_ = makeValueLabel();
    statusValue_ = makeValueLabel();

    form->addRow(QStringLiteral("Network:"), networkValue_);
    form->addRow(QStringLiteral("Blocks:"), blocksValue_);
    form->addRow(QStringLiteral("Best Block Hash:"), bestHashValue_);
    form->addRow(QStringLiteral("Connections:"), connectionsValue_);
    form->addRow(QStringLiteral("Validated Peers:"), validatedPeersValue_);
    form->addRow(QStringLiteral("Known Peers:"), peersValue_);
    form->addRow(QStringLiteral("Difficulty:"), difficultyValue_);
    form->addRow(QStringLiteral("Mempool:"), mempoolValue_);
    form->addRow(QStringLiteral("Advertised Endpoint:"), endpointValue_);
    form->addRow(QStringLiteral("Estimated Network Hashrate:"), hashrateValue_);
    form->addRow(QStringLiteral("Sync:"), syncValue_);
    form->addRow(QStringLiteral("Status:"), statusValue_);
    chainLayout->addLayout(form);
    root->addWidget(chainFrame, 1);

    updateResponsiveLayout();
}

void DashboardPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

QString DashboardPage::formatHashrate(double hps) {
    if (hps >= 1e9) return QString::number(hps / 1e9, 'f', 2) + QStringLiteral(" GH/s");
    if (hps >= 1e6) return QString::number(hps / 1e6, 'f', 2) + QStringLiteral(" MH/s");
    if (hps >= 1e3) return QString::number(hps / 1e3, 'f', 2) + QStringLiteral(" kH/s");
    return QString::number(hps, 'f', 2) + QStringLiteral(" H/s");
}

QString DashboardPage::formatCoins(qint64 sats) {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2 CryptEX")
        .arg(whole)
        .arg(frac, 8, 10, QLatin1Char('0'));
}

void DashboardPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? QStringLiteral("color:#d36b6b;") : QString());
}

void DashboardPage::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);
    updateResponsiveLayout();
}

void DashboardPage::updateResponsiveLayout() {
    if (!topRowLayout_) {
        return;
    }
    const auto nextDirection = width() < 1080 ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight;
    if (topRowLayout_->direction() != nextDirection) {
        topRowLayout_->setDirection(nextDirection);
    }
}

void DashboardPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    setStatus(QStringLiteral("Refreshing overview..."));

    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            availableValue_->setText(formatCoins(static_cast<qint64>(obj.value(QStringLiteral("balance_sats")).toInteger())));
            pendingValue_->setText(formatCoins(static_cast<qint64>(obj.value(QStringLiteral("immature_balance_sats")).toInteger())));
            lockedValue_->setText(formatCoins(static_cast<qint64>(obj.value(QStringLiteral("locked_balance_sats")).toInteger())));
            totalValue_->setText(formatCoins(static_cast<qint64>(obj.value(QStringLiteral("total_balance_sats")).toInteger())));
            const bool approved = obj.value(QStringLiteral("chain_approved")).toBool(false);
            approvalValue_->setText(approved ? QStringLiteral("Approved") : QStringLiteral("Locked until sync approval"));
            approvalValue_->setStyleSheet(approved ? QString() : QStringLiteral("color:#d6b25e;"));
        },
        [this](const QString&) {
            availableValue_->setText(QStringLiteral("-"));
            pendingValue_->setText(QStringLiteral("-"));
            lockedValue_->setText(QStringLiteral("-"));
            totalValue_->setText(QStringLiteral("-"));
            approvalValue_->setText(QStringLiteral("-"));
            approvalValue_->setStyleSheet(QString());
        });

    rpc_->call(QStringLiteral("getwallethistory"), QJsonArray{false}, this,
        [this](const QJsonValue& result) {
            recentTransactions_->clear();
            const auto rows = result.toArray();
            if (rows.isEmpty()) {
                recentTransactions_->addItem(QStringLiteral("No transactions yet."));
                return;
            }
            const int count = std::min(8, static_cast<int>(rows.size()));
            for (int i = 0; i < count; ++i) {
                recentTransactions_->addItem(rows.at(i).toString());
            }
        },
        [this](const QString&) {
            recentTransactions_->clear();
            recentTransactions_->addItem(QStringLiteral("History unavailable."));
        });

    rpc_->call(QStringLiteral("getblockchaininfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            networkValue_->setText(obj.value(QStringLiteral("chain")).toString(QStringLiteral("-")));
            const auto blocks = obj.value(QStringLiteral("blocks")).toInteger();
            const auto headers = obj.value(QStringLiteral("headers")).toInteger();
            blocksValue_->setText(QStringLiteral("%1 / %2 headers").arg(blocks).arg(headers));
            const double progress = obj.value(QStringLiteral("verificationprogress")).toDouble(1.0) * 100.0;
            const auto left = obj.value(QStringLiteral("blocksleft")).toInteger();
            const bool ibd = obj.value(QStringLiteral("initialblockdownload")).toBool(false);
            syncValue_->setText(ibd
                ? QStringLiteral("%1% synced, %2 blocks left").arg(QString::number(progress, 'f', 2)).arg(left)
                : QStringLiteral("Up to date"));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getbestblockhash"), {}, this,
        [this](const QJsonValue& result) { bestHashValue_->setText(result.toString(QStringLiteral("-"))); },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            connectionsValue_->setText(QString::number(obj.value(QStringLiteral("connections")).toInteger()));
            validatedPeersValue_->setText(QString::number(obj.value(QStringLiteral("validatedpeers")).toInteger()));
            peersValue_->setText(QString::number(obj.value(QStringLiteral("knownpeers")).toInteger()));
            endpointValue_->setText(obj.value(QStringLiteral("externalip")).toString(QStringLiteral("-")));
            setStatus(QStringLiteral("Connected to backend."));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getmempoolinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            mempoolValue_->setText(QStringLiteral("%1 tx / %2 bytes")
                .arg(obj.value(QStringLiteral("size")).toInteger())
                .arg(obj.value(QStringLiteral("bytes")).toInteger()));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getmininginfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            difficultyValue_->setText(QString::number(obj.value(QStringLiteral("difficulty")).toDouble(), 'f', 6));
            hashrateValue_->setText(QStringLiteral("%1 (from current difficulty)")
                .arg(formatHashrate(obj.value(QStringLiteral("networkhashps")).toDouble())));
        },
        [this](const QString& error) { setStatus(error, true); });
}

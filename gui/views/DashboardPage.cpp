#include "DashboardPage.hpp"
#include "rpc/RpcClient.hpp"

#include <algorithm>
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

    auto* topRow = new QHBoxLayout();
    topRow->setSpacing(12);

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
    totalValue_ = makeValueLabel();
    balancesForm->addRow(QStringLiteral("Available:"), availableValue_);
    balancesForm->addRow(QStringLiteral("Pending:"), pendingValue_);
    balancesForm->addRow(QStringLiteral("Total:"), totalValue_);
    balancesLayout->addLayout(balancesForm);
    balancesLayout->addStretch(1);
    topRow->addWidget(balancesFrame, 1);

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
    topRow->addWidget(txFrame, 1);

    root->addLayout(topRow, 1);

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
    peersValue_ = makeValueLabel();
    difficultyValue_ = makeValueLabel();
    mempoolValue_ = makeValueLabel();
    endpointValue_ = makeValueLabel();
    hashrateValue_ = makeValueLabel();
    statusValue_ = makeValueLabel();

    form->addRow(QStringLiteral("Network:"), networkValue_);
    form->addRow(QStringLiteral("Blocks:"), blocksValue_);
    form->addRow(QStringLiteral("Best Block Hash:"), bestHashValue_);
    form->addRow(QStringLiteral("Connections:"), connectionsValue_);
    form->addRow(QStringLiteral("Known Peers:"), peersValue_);
    form->addRow(QStringLiteral("Difficulty:"), difficultyValue_);
    form->addRow(QStringLiteral("Mempool:"), mempoolValue_);
    form->addRow(QStringLiteral("Advertised Endpoint:"), endpointValue_);
    form->addRow(QStringLiteral("Estimated Network Hashrate:"), hashrateValue_);
    form->addRow(QStringLiteral("Status:"), statusValue_);
    chainLayout->addLayout(form);
    root->addWidget(chainFrame, 1);
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
            totalValue_->setText(formatCoins(static_cast<qint64>(obj.value(QStringLiteral("total_balance_sats")).toInteger())));
        },
        [this](const QString&) {
            availableValue_->setText(QStringLiteral("-"));
            pendingValue_->setText(QStringLiteral("-"));
            totalValue_->setText(QStringLiteral("-"));
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
            blocksValue_->setText(QString::number(obj.value(QStringLiteral("blocks")).toInteger()));
        },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getbestblockhash"), {}, this,
        [this](const QJsonValue& result) { bestHashValue_->setText(result.toString(QStringLiteral("-"))); },
        [this](const QString& error) { setStatus(error, true); });

    rpc_->call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            connectionsValue_->setText(QString::number(obj.value(QStringLiteral("connections")).toInteger()));
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

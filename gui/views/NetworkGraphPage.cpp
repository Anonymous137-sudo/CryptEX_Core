#include "NetworkGraphPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QDateTime>
#include <QAbstractItemView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QFormLayout>
#include <QFrame>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QTableWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>
#include <memory>
#include <optional>

namespace {

class GraphCanvas final : public QWidget {
public:
    explicit GraphCanvas(QWidget* parent = nullptr)
        : QWidget(parent) {
        setMinimumHeight(320);
    }

    void append(double blocks, double connections, double hashrate) {
        appendSeries(blockSeries_, blocks);
        appendSeries(connectionSeries_, connections);
        appendSeries(hashrateSeries_, hashrate);
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), QColor("#000000"));

        const QRect plot = rect().adjusted(18, 18, -18, -36);
        painter.setPen(QColor("#123318"));
        for (int i = 0; i <= 4; ++i) {
            const int y = plot.top() + ((plot.height() * i) / 4);
            painter.drawLine(plot.left(), y, plot.right(), y);
        }
        for (int i = 0; i <= 5; ++i) {
            const int x = plot.left() + ((plot.width() * i) / 5);
            painter.drawLine(x, plot.top(), x, plot.bottom());
        }

        drawSeries(painter, plot, blockSeries_, QColor("#56ff78"));
        drawSeries(painter, plot, connectionSeries_, QColor("#21c55d"));
        drawSeries(painter, plot, hashrateSeries_, QColor("#9affb3"));

        painter.setPen(QColor("#7dff90"));
        painter.drawText(QRect(plot.left(), rect().bottom() - 22, rect().width() - 36, 18),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Blocks"));
        painter.setPen(QColor("#21c55d"));
        painter.drawText(QRect(plot.left() + 90, rect().bottom() - 22, rect().width() - 36, 18),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Connections"));
        painter.setPen(QColor("#9affb3"));
        painter.drawText(QRect(plot.left() + 220, rect().bottom() - 22, rect().width() - 36, 18),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Hashrate"));
    }

private:
    void appendSeries(QVector<double>& series, double value) {
        series.push_back(value);
        constexpr int maxPoints = 120;
        if (series.size() > maxPoints) {
            series.remove(0, series.size() - maxPoints);
        }
    }

    void drawSeries(QPainter& painter, const QRect& plot, const QVector<double>& series, const QColor& color) {
        if (series.isEmpty()) {
            return;
        }

        double minValue = *std::min_element(series.begin(), series.end());
        double maxValue = *std::max_element(series.begin(), series.end());
        if (std::abs(maxValue - minValue) < 0.000001) {
            maxValue += 1.0;
            minValue -= 1.0;
        }

        QPainterPath path;
        for (int i = 0; i < series.size(); ++i) {
            const double xRatio = series.size() == 1 ? 1.0 : static_cast<double>(i) / static_cast<double>(series.size() - 1);
            const double yRatio = (series.at(i) - minValue) / (maxValue - minValue);
            const qreal x = plot.left() + (plot.width() * xRatio);
            const qreal y = plot.bottom() - (plot.height() * yRatio);
            if (i == 0) path.moveTo(x, y);
            else path.lineTo(x, y);
        }

        painter.setPen(QPen(color, 2.0));
        painter.drawPath(path);
    }

    QVector<double> blockSeries_;
    QVector<double> connectionSeries_;
    QVector<double> hashrateSeries_;
};

class TopologyCanvas final : public QWidget {
public:
    explicit TopologyCanvas(QWidget* parent = nullptr)
        : QWidget(parent) {
        setMinimumHeight(320);
    }

    void setPeers(const QJsonArray& peers) {
        peers_ = peers;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), QColor("#000000"));

        const QRect bounds = rect().adjusted(18, 18, -18, -18);
        painter.setPen(QColor("#123318"));
        painter.drawRoundedRect(bounds, 12, 12);

        const QPointF center(bounds.center().x(), bounds.center().y() + 8.0);
        const qreal radius = std::max<qreal>(80.0, std::min(bounds.width(), bounds.height()) * 0.33);

        painter.setPen(QColor("#7dff90"));
        painter.drawText(QRect(bounds.left(), bounds.top(), bounds.width(), 20),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Topology View"));

        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor("#0d3d1e"));
        painter.drawEllipse(center, 24, 24);
        painter.setPen(QColor("#d8ffe1"));
        painter.drawText(QRectF(center.x() - 54, center.y() - 10, 108, 20),
                         Qt::AlignCenter,
                         QStringLiteral("This node"));

        if (peers_.isEmpty()) {
            painter.setPen(QColor("#7dff90"));
            painter.drawText(QRect(bounds.left(), bounds.top() + 28, bounds.width(), bounds.height() - 28),
                             Qt::AlignCenter,
                             QStringLiteral("No known peers yet."));
            return;
        }

        const int count = peers_.size();
        for (int i = 0; i < count; ++i) {
            const auto obj = peers_.at(i).toObject();
            const bool banned = obj.value(QStringLiteral("banned")).toBool(false);
            const bool connected = obj.value(QStringLiteral("connected")).toBool(false);
            const QColor nodeColor = banned ? QColor("#f87171")
                                            : (connected ? QColor("#63ff7d") : QColor("#d6b25e"));
            const QColor edgeColor = banned ? QColor("#7f1d1d")
                                            : (connected ? QColor("#1f6f38") : QColor("#6b571d"));
            const double angle = (6.28318530717958647692 * static_cast<double>(i)) / static_cast<double>(count);
            const QPointF peerPoint(center.x() + std::cos(angle) * radius,
                                    center.y() + std::sin(angle) * radius);

            painter.setPen(QPen(edgeColor, connected ? 2.2 : 1.4));
            painter.drawLine(center, peerPoint);

            painter.setPen(Qt::NoPen);
            painter.setBrush(nodeColor);
            painter.drawEllipse(peerPoint, connected ? 12 : 9, connected ? 12 : 9);

            painter.setPen(QColor("#d8ffe1"));
            const QString label = obj.value(QStringLiteral("addr")).toString();
            const QString compact = label.size() > 22
                ? label.left(10) + QStringLiteral("...") + label.right(9)
                : label;
            const QRectF textRect(peerPoint.x() - 55, peerPoint.y() + 14, 110, 28);
            painter.drawText(textRect, Qt::AlignHCenter | Qt::AlignTop, compact);
        }

        painter.setPen(QColor("#63ff7d"));
        painter.drawText(QRect(bounds.left(), bounds.bottom() - 18, bounds.width(), 18),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Connected"));
        painter.setPen(QColor("#d6b25e"));
        painter.drawText(QRect(bounds.left() + 110, bounds.bottom() - 18, bounds.width(), 18),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Known"));
        painter.setPen(QColor("#f87171"));
        painter.drawText(QRect(bounds.left() + 190, bounds.bottom() - 18, bounds.width(), 18),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         QStringLiteral("Banned"));
    }

private:
    QJsonArray peers_;
};

} // namespace

NetworkGraphPage::NetworkGraphPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    setStyleSheet(
        "QLabel { color: #63ff7d; }"
        "QWidget { background: transparent; }");

    auto* title = new QLabel(QStringLiteral("Network Graph"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    snapshotLabel_ = new QLabel(QStringLiteral("Waiting for network data..."), this);
    snapshotLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(snapshotLabel_);

    auto* statusFrame = new QFrame(this);
    statusFrame->setObjectName(QStringLiteral("panelFrame"));
    auto* statusLayout = new QFormLayout(statusFrame);
    statusLayout->setContentsMargins(12, 10, 12, 10);
    statusLayout->setHorizontalSpacing(18);
    statusLayout->setVerticalSpacing(8);

    approvalLabel_ = new QLabel(QStringLiteral("-"), statusFrame);
    lockedLabel_ = new QLabel(QStringLiteral("-"), statusFrame);
    peersLabel_ = new QLabel(QStringLiteral("-"), statusFrame);
    checkpointLabel_ = new QLabel(QStringLiteral("-"), statusFrame);
    mappingLabel_ = new QLabel(QStringLiteral("-"), statusFrame);
    approvalLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lockedLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    peersLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    checkpointLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mappingLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    statusLayout->addRow(QStringLiteral("Chain approval:"), approvalLabel_);
    statusLayout->addRow(QStringLiteral("Locked funds:"), lockedLabel_);
    statusLayout->addRow(QStringLiteral("Validated peers:"), peersLabel_);
    statusLayout->addRow(QStringLiteral("Checkpoint:"), checkpointLabel_);
    statusLayout->addRow(QStringLiteral("Port mapping:"), mappingLabel_);
    root->addWidget(statusFrame);

    graph_ = new GraphCanvas(this);
    root->addWidget(graph_, 1);

    auto* topologyFrame = new QFrame(this);
    topologyFrame->setObjectName(QStringLiteral("panelFrame"));
    auto* topologyLayout = new QVBoxLayout(topologyFrame);
    topologyLayout->setContentsMargins(12, 10, 12, 10);
    topologyLayout->setSpacing(8);
    auto* topologyTitle = new QLabel(QStringLiteral("Peer Topology"), topologyFrame);
    topologyTitle->setObjectName(QStringLiteral("sectionTitle"));
    topologyLayout->addWidget(topologyTitle);
    topology_ = new TopologyCanvas(topologyFrame);
    topologyLayout->addWidget(topology_, 1);
    root->addWidget(topologyFrame, 1);

    auto* peerFrame = new QFrame(this);
    peerFrame->setObjectName(QStringLiteral("panelFrame"));
    auto* peerLayout = new QVBoxLayout(peerFrame);
    peerLayout->setContentsMargins(12, 10, 12, 10);
    peerLayout->setSpacing(8);
    auto* peerTitle = new QLabel(QStringLiteral("Persistent Peer Graph"), peerFrame);
    peerTitle->setObjectName(QStringLiteral("sectionTitle"));
    peerLayout->addWidget(peerTitle);
    peerTable_ = new QTableWidget(peerFrame);
    peerTable_->setColumnCount(7);
    peerTable_->setHorizontalHeaderLabels({
        QStringLiteral("Peer"),
        QStringLiteral("Source"),
        QStringLiteral("Netgroup"),
        QStringLiteral("Score"),
        QStringLiteral("Success / Fail"),
        QStringLiteral("Height"),
        QStringLiteral("State")
    });
    peerTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    peerTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    peerTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    peerTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    peerTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    peerTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    peerTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    peerTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    peerTable_->setSelectionMode(QAbstractItemView::NoSelection);
    peerLayout->addWidget(peerTable_);
    root->addWidget(peerFrame, 1);

    statusLabel_ = new QLabel(QStringLiteral("-"), this);
    statusLabel_->setWordWrap(true);
    root->addWidget(statusLabel_);
}

void NetworkGraphPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void NetworkGraphPage::refresh() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }

    setStatus(QStringLiteral("Refreshing network graph..."));

    struct PendingState {
        int completed{0};
        std::optional<double> blocks;
        std::optional<double> connections;
        std::optional<double> hashrate;
        QString error;
    };
    auto pending = std::make_shared<PendingState>();

    auto finish = [this, pending]() {
        ++pending->completed;
        if (pending->completed < 3) {
            return;
        }
        if (pending->blocks && pending->connections && pending->hashrate) {
            appendSample(*pending->blocks, *pending->connections, *pending->hashrate);
            snapshotLabel_->setText(
                QStringLiteral("Latest sample | Blocks: %1 | Connections: %2 | Network Hashrate: %3 | %4")
                    .arg(QString::number(*pending->blocks, 'f', 0))
                    .arg(QString::number(*pending->connections, 'f', 0))
                    .arg(formatHashrate(*pending->hashrate))
                    .arg(QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"))));
            setStatus(QStringLiteral("Network graph updated."));
        } else {
            setStatus(pending->error.isEmpty() ? QStringLiteral("Network graph update failed.") : pending->error, true);
        }
    };

    rpc_->call(QStringLiteral("getblockchaininfo"), {}, this,
        [this, pending, finish](const QJsonValue& result) {
            const auto obj = result.toObject();
            pending->blocks = static_cast<double>(obj.value(QStringLiteral("blocks")).toInteger());
            const bool approved = obj.value(QStringLiteral("chain_approved")).toBool(false);
            approvalLabel_->setText(approved ? QStringLiteral("Approved")
                                             : QStringLiteral("Locked until sync approval"));
            approvalLabel_->setStyleSheet(approved ? QStringLiteral("color:#63ff7d;")
                                                   : QStringLiteral("color:#d6b25e;"));
            finish();
        },
        [pending, finish](const QString& error) {
            pending->error = error;
            finish();
        });

    rpc_->call(QStringLiteral("getnetworkinfo"), {}, this,
        [pending, finish](const QJsonValue& result) {
            pending->connections = static_cast<double>(result.toObject().value(QStringLiteral("connections")).toInteger());
            finish();
        },
        [pending, finish](const QString& error) {
            pending->error = error;
            finish();
        });

    rpc_->call(QStringLiteral("getmininginfo"), {}, this,
        [pending, finish](const QJsonValue& result) {
            pending->hashrate = result.toObject().value(QStringLiteral("networkhashps")).toDouble();
            finish();
        },
        [pending, finish](const QString& error) {
            pending->error = error;
            finish();
        });

    rpc_->call(QStringLiteral("getnetworkinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto validated = obj.value(QStringLiteral("validatedpeers")).toInteger();
            const auto total = obj.value(QStringLiteral("connections")).toInteger();
            const bool syncing = obj.value(QStringLiteral("syncing")).toBool(false);
            peersLabel_->setText(QStringLiteral("%1 validated / %2 connected%3")
                .arg(validated)
                .arg(total)
                .arg(syncing ? QStringLiteral(" (syncing)") : QString()));
            peersLabel_->setStyleSheet(QStringLiteral("color:#63ff7d;"));
            const bool mappingActive = obj.value(QStringLiteral("portmapping_active")).toBool(false);
            const auto mappingProto = obj.value(QStringLiteral("portmapping_protocol")).toString();
            const auto mappingExternal = obj.value(QStringLiteral("portmapping_external")).toString();
            if (mappingActive) {
                mappingLabel_->setText(QStringLiteral("%1 %2")
                    .arg(mappingProto.isEmpty() ? QStringLiteral("mapped") : mappingProto)
                    .arg(mappingExternal));
                mappingLabel_->setStyleSheet(QStringLiteral("color:#63ff7d;"));
            } else {
                const auto message = obj.value(QStringLiteral("portmapping_message")).toString(QStringLiteral("inactive"));
                mappingLabel_->setText(message);
                mappingLabel_->setStyleSheet(QStringLiteral("color:#d6b25e;"));
            }
        },
        [this](const QString&) {
            peersLabel_->setText(QStringLiteral("Unavailable"));
            peersLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
            mappingLabel_->setText(QStringLiteral("Unavailable"));
            mappingLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
        });

    rpc_->call(QStringLiteral("getwalletinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            const auto locked = static_cast<qint64>(obj.value(QStringLiteral("locked_balance_sats")).toInteger());
            lockedLabel_->setText(formatCoins(locked));
            lockedLabel_->setStyleSheet(locked > 0 ? QStringLiteral("color:#d6b25e;")
                                                   : QStringLiteral("color:#63ff7d;"));
        },
        [this](const QString&) {
            lockedLabel_->setText(QStringLiteral("Wallet unavailable"));
            lockedLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
        });

    rpc_->call(QStringLiteral("getcheckpointinfo"), {}, this,
        [this](const QJsonValue& result) {
            const auto obj = result.toObject();
            if (!obj.value(QStringLiteral("present")).toBool(false)) {
                checkpointLabel_->setText(QStringLiteral("None"));
                checkpointLabel_->setStyleSheet(QStringLiteral("color:#d6b25e;"));
                return;
            }
            const auto height = obj.value(QStringLiteral("height")).toInteger();
            const auto pinned = obj.value(QStringLiteral("pinned")).toBool(false);
            checkpointLabel_->setText(QStringLiteral("%1 at height %2")
                .arg(pinned ? QStringLiteral("Pinned") : QStringLiteral("Auto"))
                .arg(height));
            checkpointLabel_->setStyleSheet(pinned ? QStringLiteral("color:#63ff7d;")
                                                  : QStringLiteral("color:#9affb3;"));
        },
        [this](const QString&) {
            checkpointLabel_->setText(QStringLiteral("Unavailable"));
            checkpointLabel_->setStyleSheet(QStringLiteral("color:#d36b6b;"));
        });

    rpc_->call(QStringLiteral("getpeergraph"), {}, this,
        [this](const QJsonValue& result) {
            const auto rows = result.toArray();
            static_cast<TopologyCanvas*>(topology_)->setPeers(rows);
            peerTable_->setRowCount(rows.size());
            for (int i = 0; i < rows.size(); ++i) {
                const auto obj = rows.at(i).toObject();
                const auto score = obj.value(QStringLiteral("banscore")).toInteger();
                const auto connected = obj.value(QStringLiteral("connected")).toBool(false);
                const auto banned = obj.value(QStringLiteral("banned")).toBool(false);
                const auto state = banned ? QStringLiteral("banned")
                                          : (connected ? QStringLiteral("connected") : QStringLiteral("known"));
                peerTable_->setItem(i, 0, new QTableWidgetItem(obj.value(QStringLiteral("addr")).toString()));
                peerTable_->setItem(i, 1, new QTableWidgetItem(obj.value(QStringLiteral("source")).toString()));
                peerTable_->setItem(i, 2, new QTableWidgetItem(obj.value(QStringLiteral("netgroup")).toString()));
                peerTable_->setItem(i, 3, new QTableWidgetItem(QString::number(score)));
                peerTable_->setItem(i, 4, new QTableWidgetItem(QStringLiteral("%1 / %2")
                    .arg(obj.value(QStringLiteral("successful_connections")).toInteger())
                    .arg(obj.value(QStringLiteral("failed_connections")).toInteger())));
                peerTable_->setItem(i, 5, new QTableWidgetItem(QString::number(obj.value(QStringLiteral("startingheight")).toInteger())));
                peerTable_->setItem(i, 6, new QTableWidgetItem(state));
            }
        },
        [this](const QString&) {
            static_cast<TopologyCanvas*>(topology_)->setPeers(QJsonArray{});
            peerTable_->setRowCount(0);
        });
}

void NetworkGraphPage::setStatus(const QString& text, bool error) {
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(error ? QStringLiteral("color:#d36b6b;") : QStringLiteral("color:#63ff7d;"));
}

void NetworkGraphPage::appendSample(double blocks, double connections, double hashrate) {
    static_cast<GraphCanvas*>(graph_)->append(blocks, connections, hashrate);
}

QString NetworkGraphPage::formatHashrate(double hps) const {
    if (hps >= 1e9) return QString::number(hps / 1e9, 'f', 2) + QStringLiteral(" GH/s");
    if (hps >= 1e6) return QString::number(hps / 1e6, 'f', 2) + QStringLiteral(" MH/s");
    if (hps >= 1e3) return QString::number(hps / 1e3, 'f', 2) + QStringLiteral(" kH/s");
    return QString::number(hps, 'f', 2) + QStringLiteral(" H/s");
}

QString NetworkGraphPage::formatCoins(qint64 sats) const {
    const qint64 whole = sats / 100000000LL;
    const qint64 frac = qAbs(sats % 100000000LL);
    return QStringLiteral("%1.%2 CryptEX")
        .arg(whole)
        .arg(frac, 8, 10, QLatin1Char('0'));
}

#include "NetworkGraphPage.hpp"
#include "rpc/RpcClient.hpp"

#include <QDateTime>
#include <QJsonObject>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
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

    graph_ = new GraphCanvas(this);
    root->addWidget(graph_, 1);

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
        [pending, finish](const QJsonValue& result) {
            pending->blocks = static_cast<double>(result.toObject().value(QStringLiteral("blocks")).toInteger());
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

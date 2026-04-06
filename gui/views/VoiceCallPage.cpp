#include "VoiceCallPage.hpp"

#include "ChatTheme.hpp"
#include "rpc/RpcClient.hpp"

#include <QAudioDevice>
#include <QAudioFormat>
#include <QAudioSink>
#include <QAudioSource>
#include <QByteArray>
#include <QCheckBox>
#include <QDateTime>
#include <QFrame>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMediaDevices>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QSplitter>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace {

QPixmap anonymousAvatarPixmap(const QSize& size) {
    QPixmap pixmap(size);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF bounds(2.0, 2.0, size.width() - 4.0, size.height() - 4.0);
    const QPointF center = bounds.center();

    QRadialGradient bg(center, bounds.width() * 0.55);
    bg.setColorAt(0.0, QColor(19, 46, 62));
    bg.setColorAt(0.55, QColor(10, 15, 29));
    bg.setColorAt(1.0, QColor(5, 6, 16));
    painter.setPen(QPen(QColor(20, 216, 255, 220), 2.0));
    painter.setBrush(bg);
    painter.drawEllipse(bounds);

    painter.setPen(QPen(QColor(255, 72, 108, 200), 1.4));
    painter.drawArc(bounds.adjusted(8, 8, -8, -8), 34 * 16, 220 * 16);

    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(175, 255, 255, 225));
    painter.drawEllipse(QRectF(center.x() - 16.0, center.y() - 30.0, 32.0, 32.0));

    QPainterPath shoulders;
    shoulders.moveTo(center.x() - 32.0, center.y() + 28.0);
    shoulders.cubicTo(center.x() - 25.0, center.y() + 6.0,
                      center.x() + 25.0, center.y() + 6.0,
                      center.x() + 32.0, center.y() + 28.0);
    shoulders.lineTo(center.x() + 22.0, center.y() + 44.0);
    shoulders.lineTo(center.x() - 22.0, center.y() + 44.0);
    shoulders.closeSubpath();
    painter.setBrush(QColor(94, 244, 255, 205));
    painter.drawPath(shoulders);

    painter.setPen(QPen(QColor(255, 72, 108, 170), 1.1));
    painter.drawLine(QPointF(center.x() - 20.0, center.y() + 38.0), QPointF(center.x() + 20.0, center.y() + 38.0));
    return pixmap;
}

class VoiceWaveformView final : public QWidget {
public:
    explicit VoiceWaveformView(QWidget* parent = nullptr)
        : QWidget(parent) {
        setMinimumHeight(180);
    }

    void setOutgoingLevels(const QVector<float>& levels) {
        outgoing_ = levels;
        update();
    }

    void setIncomingLevels(const QVector<float>& levels) {
        incoming_ = levels;
        update();
    }

    void clearLevels() {
        outgoing_.clear();
        incoming_.clear();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), QColor(7, 8, 20));

        const QRectF frame = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
        painter.setPen(QPen(QColor(20, 216, 255, 145), 1.0));
        painter.drawRoundedRect(frame, 12.0, 12.0);

        const QRectF grid = frame.adjusted(14, 14, -14, -14);
        painter.save();
        painter.setClipRect(grid);
        painter.setPen(QPen(QColor(20, 216, 255, 30), 1.0));
        for (int i = 0; i <= 10; ++i) {
            const qreal x = grid.left() + (grid.width() * i / 10.0);
            painter.drawLine(QPointF(x, grid.top()), QPointF(x, grid.bottom()));
        }
        for (int i = 0; i <= 6; ++i) {
            const qreal y = grid.top() + (grid.height() * i / 6.0);
            painter.drawLine(QPointF(grid.left(), y), QPointF(grid.right(), y));
        }
        const qreal midY = grid.center().y();
        painter.setPen(QPen(QColor(255, 72, 108, 150), 1.2));
        painter.drawLine(QPointF(grid.left(), midY), QPointF(grid.right(), midY));

        if (outgoing_.isEmpty() && incoming_.isEmpty()) {
            painter.setPen(QColor(112, 202, 217, 170));
            painter.drawText(grid, Qt::AlignCenter,
                             QStringLiteral("Live anonymous waveform\ncyan = local voice, red = remote voice"));
            painter.restore();
            return;
        }

        auto drawWave = [&](const QVector<float>& samples, const QColor& primary, bool upperHalf) {
            if (samples.isEmpty()) return;
            const int count = samples.size();
            const qreal step = count > 1 ? grid.width() / qreal(count - 1) : grid.width();
            QPainterPath path;
            for (int i = 0; i < count; ++i) {
                const qreal x = grid.left() + step * i;
                const qreal amplitude = qBound(0.0, static_cast<double>(samples.at(i)), 1.0);
                const qreal extent = grid.height() * 0.42 * amplitude;
                const qreal y = upperHalf ? (midY - extent) : (midY + extent);
                if (i == 0) path.moveTo(x, y);
                else path.lineTo(x, y);
            }
            painter.setPen(QPen(primary.darker(160), 5.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            painter.drawPath(path);
            painter.setPen(QPen(primary, 2.1, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            painter.drawPath(path);
        };

        drawWave(outgoing_, QColor(20, 216, 255), true);
        drawWave(incoming_, QColor(255, 72, 108), false);
        painter.restore();
    }

private:
    QVector<float> outgoing_;
    QVector<float> incoming_;
};

class PlaybackBufferDevice final : public QIODevice {
public:
    explicit PlaybackBufferDevice(QObject* parent = nullptr)
        : QIODevice(parent) {
        open(QIODevice::ReadOnly);
    }

    void enqueue(const QByteArray& bytes) {
        if (bytes.isEmpty()) return;
        buffer_.append(bytes);
        constexpr int kMaxBufferedBytes = 32000 * 4;
        if (buffer_.size() > kMaxBufferedBytes) {
            buffer_.remove(0, buffer_.size() - kMaxBufferedBytes);
        }
    }

    void clear() {
        buffer_.clear();
    }

    bool isSequential() const override { return true; }
    qint64 bytesAvailable() const override {
        return std::max<qint64>(buffer_.size(), 4096) + QIODevice::bytesAvailable();
    }

protected:
    qint64 readData(char* data, qint64 maxlen) override {
        if (maxlen <= 0) return 0;
        const qint64 copied = std::min<qint64>(maxlen, buffer_.size());
        if (copied > 0) {
            std::memcpy(data, buffer_.constData(), static_cast<size_t>(copied));
            buffer_.remove(0, static_cast<int>(copied));
        }
        if (copied < maxlen) {
            std::memset(data + copied, 0, static_cast<size_t>(maxlen - copied));
        }
        return maxlen;
    }

    qint64 writeData(const char*, qint64) override {
        return -1;
    }

private:
    QByteArray buffer_;
};

QString formatTimestamp(quint64 unixTs) {
    if (unixTs == 0) return QStringLiteral("-");
    const auto dt = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(unixTs));
    return dt.isValid() ? dt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")) : QString::number(unixTs);
}

QString formatDuration(quint64 seconds) {
    const quint64 hrs = seconds / 3600;
    const quint64 mins = (seconds % 3600) / 60;
    const quint64 secs = seconds % 60;
    return QStringLiteral("%1:%2:%3")
        .arg(hrs, 2, 10, QLatin1Char('0'))
        .arg(mins, 2, 10, QLatin1Char('0'))
        .arg(secs, 2, 10, QLatin1Char('0'));
}

int bytesPerFrame(const QAudioFormat& format) {
    const int bytesPerSample = format.bytesPerSample();
    const int channels = format.channelCount();
    return bytesPerSample > 0 && channels > 0 ? bytesPerSample * channels : 0;
}

QAudioFormat makeInt16Format(int sampleRate, int channels) {
    QAudioFormat format;
    format.setSampleRate(sampleRate);
    format.setChannelCount(channels);
    format.setSampleFormat(QAudioFormat::Int16);
    return format;
}

bool isOpusSupportedRate(int sampleRate) {
    switch (sampleRate) {
    case 8000:
    case 12000:
    case 16000:
    case 24000:
    case 48000:
        return true;
    default:
        return false;
    }
}

QAudioFormat chooseSharedFormat(const QAudioDevice& inputDevice,
                                const QAudioDevice& outputDevice,
                                int requestedRate,
                                int requestedChannels,
                                int bitsPerSample) {
    const int channels = std::max(1, requestedChannels);
    QList<QAudioFormat> candidates;
    if (bitsPerSample == 16) {
        candidates << makeInt16Format(std::max(8000, requestedRate), channels)
                   << makeInt16Format(16000, channels)
                   << makeInt16Format(24000, channels)
                   << makeInt16Format(48000, channels)
                   << makeInt16Format(12000, channels)
                   << makeInt16Format(8000, channels)
                   << makeInt16Format(16000, 1)
                   << makeInt16Format(48000, 1);
    }
    for (const auto& candidate : candidates) {
        if (inputDevice.isFormatSupported(candidate) && outputDevice.isFormatSupported(candidate)) {
            return candidate;
        }
    }
    auto preferred = inputDevice.preferredFormat();
    if (preferred.sampleFormat() == QAudioFormat::Int16 &&
        isOpusSupportedRate(preferred.sampleRate()) &&
        outputDevice.isFormatSupported(preferred)) {
        return preferred;
    }
    auto outputPreferred = outputDevice.preferredFormat();
    if (outputPreferred.sampleFormat() == QAudioFormat::Int16 &&
        isOpusSupportedRate(outputPreferred.sampleRate()) &&
        inputDevice.isFormatSupported(outputPreferred)) {
        return outputPreferred;
    }
    return makeInt16Format(16000, 1);
}

QVector<float> levelsFromPcm16(const QByteArray& pcm, int channels, int buckets = 96) {
    if (pcm.isEmpty() || channels <= 0) return {};
    const int sampleCount = pcm.size() / 2;
    if (sampleCount <= 0) return {};
    const auto* samples = reinterpret_cast<const qint16*>(pcm.constData());
    const int frameCount = sampleCount / channels;
    if (frameCount <= 0) return {};

    QVector<float> raw;
    raw.reserve(frameCount);
    for (int frame = 0; frame < frameCount; ++frame) {
        float level = 0.0f;
        for (int channel = 0; channel < channels; ++channel) {
            const int index = frame * channels + channel;
            level += std::abs(static_cast<int>(samples[index])) / 32768.0f;
        }
        raw.push_back(level / channels);
    }

    QVector<float> reduced;
    reduced.reserve(buckets);
    for (int i = 0; i < buckets; ++i) {
        const int start = (raw.size() * i) / buckets;
        const int end = std::max(start + 1, static_cast<int>((raw.size() * (i + 1)) / buckets));
        float sum = 0.0f;
        for (int j = start; j < end && j < raw.size(); ++j) {
            sum += raw.at(j);
        }
        reduced.push_back(sum / std::max(1, end - start));
    }
    return reduced;
}

QByteArray obfuscatePcm16Chunk(const QByteArray& pcm, int channels) {
    if (pcm.isEmpty() || channels <= 0 || (pcm.size() % (channels * 2)) != 0) {
        return pcm;
    }
    const int frameCount = pcm.size() / (channels * 2);
    if (frameCount <= 0) return pcm;

    const auto* input = reinterpret_cast<const qint16*>(pcm.constData());
    constexpr double kPitchFactor = 0.82;
    const int outputFrames = static_cast<int>(std::ceil(frameCount / kPitchFactor));
    QByteArray out(outputFrames * channels * 2, Qt::Uninitialized);
    auto* output = reinterpret_cast<qint16*>(out.data());

    auto sampleAt = [&](int frame, int channel) -> qint16 {
        return input[(frame * channels) + channel];
    };

    for (int outFrame = 0; outFrame < outputFrames; ++outFrame) {
        const double srcPos = std::min<double>(frameCount - 1, outFrame * kPitchFactor);
        const int base = static_cast<int>(srcPos);
        const int next = std::min(frameCount - 1, base + 1);
        const double alpha = srcPos - base;
        for (int channel = 0; channel < channels; ++channel) {
            const double left = static_cast<double>(sampleAt(base, channel));
            const double right = static_cast<double>(sampleAt(next, channel));
            double sample = left + ((right - left) * alpha);
            if (outFrame > 0) {
                const double prev = static_cast<double>(output[((outFrame - 1) * channels) + channel]);
                sample = (sample * 0.78) + (prev * 0.22);
            }
            output[(outFrame * channels) + channel] = static_cast<qint16>(std::clamp(sample, -32768.0, 32767.0));
        }
    }
    return out;
}

} // namespace

VoiceCallPage::VoiceCallPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    auto* title = new QLabel(QStringLiteral("Voice Call Relay"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    statusValue_ = new QLabel(QStringLiteral("Ephemeral address-to-address voice relay. No call logs. No recording. Live state only."), this);
    statusValue_->setWordWrap(true);
    root->addWidget(statusValue_);

    auto* mainSplitter = new QSplitter(Qt::Vertical, this);
    mainSplitter->setChildrenCollapsible(false);
    root->addWidget(mainSplitter, 1);

    auto* hero = new QFrame(mainSplitter);
    hero->setObjectName(QStringLiteral("audioPreviewCard"));
    auto* heroLayout = new QGridLayout(hero);
    heroLayout->setContentsMargins(14, 14, 14, 14);
    heroLayout->setHorizontalSpacing(14);
    heroLayout->setVerticalSpacing(10);

    avatarLabel_ = new QLabel(hero);
    avatarLabel_->setPixmap(anonymousAvatarPixmap(QSize(120, 120)));
    avatarLabel_->setFixedSize(120, 120);
    avatarLabel_->setAlignment(Qt::AlignCenter);
    heroLayout->addWidget(avatarLabel_, 0, 0, 3, 1, Qt::AlignTop);

    callStateValue_ = new QLabel(QStringLiteral("Standby"), hero);
    callStateValue_->setObjectName(QStringLiteral("audioPreviewTitle"));
    heroLayout->addWidget(callStateValue_, 0, 1);

    routeValue_ = new QLabel(QStringLiteral("No active call"), hero);
    routeValue_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    routeValue_->setWordWrap(true);
    heroLayout->addWidget(routeValue_, 1, 1);

    timestampValue_ = new QLabel(QStringLiteral("-"), hero);
    timestampValue_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    heroLayout->addWidget(timestampValue_, 2, 1);

    ringStateValue_ = new QLabel(QStringLiteral("Call state: idle"), hero);
    ringStateValue_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    heroLayout->addWidget(ringStateValue_, 0, 2);

    latencyValue_ = new QLabel(QStringLiteral("Latency: -"), hero);
    latencyValue_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    heroLayout->addWidget(latencyValue_, 1, 2);

    qualityValue_ = new QLabel(QStringLiteral("Quality: standby"), hero);
    qualityValue_->setObjectName(QStringLiteral("audioAttachmentMeta"));
    heroLayout->addWidget(qualityValue_, 2, 2);

    securityValue_ = new QLabel(QStringLiteral("Security: ECDH session | AES-GCM frames | opus | voice-cloak available"), hero);
    securityValue_->setObjectName(QStringLiteral("audioTranscriptStatus"));
    securityValue_->setWordWrap(true);
    heroLayout->addWidget(securityValue_, 3, 0, 1, 3);

    waveformView_ = new VoiceWaveformView(hero);
    heroLayout->addWidget(waveformView_, 4, 0, 1, 3);
    mainSplitter->addWidget(hero);

    auto* lowerPane = new QWidget(mainSplitter);
    auto* lowerLayout = new QVBoxLayout(lowerPane);
    lowerLayout->setContentsMargins(0, 0, 0, 0);
    lowerLayout->setSpacing(10);

    auto* configBox = new QGroupBox(QStringLiteral("Call Setup"), lowerPane);
    auto* configLayout = new QFormLayout(configBox);
    configLayout->setContentsMargins(12, 12, 12, 12);
    configLayout->setHorizontalSpacing(10);
    configLayout->setVerticalSpacing(8);

    recipientEdit_ = new QLineEdit(lowerPane);
    recipientEdit_->setPlaceholderText(QStringLiteral("Recipient blockchain address"));
    recipientPubkeyEdit_ = new QLineEdit(lowerPane);
    recipientPubkeyEdit_->setPlaceholderText(QStringLiteral("Recipient secp256k1 pubkey (Base64)"));
    peerEdit_ = new QLineEdit(lowerPane);
    peerEdit_->setPlaceholderText(QStringLiteral("Optional direct peer override (host:port)"));
    fromAddressEdit_ = new QLineEdit(lowerPane);
    fromAddressEdit_->setPlaceholderText(QStringLiteral("Optional local address override"));
    obfuscateCheck_ = new QCheckBox(QStringLiteral("Apply live voice cloak before transmit"), lowerPane);
    obfuscateCheck_->setChecked(true);

    configLayout->addRow(QStringLiteral("Recipient Address"), recipientEdit_);
    configLayout->addRow(QStringLiteral("Recipient Pubkey"), recipientPubkeyEdit_);
    configLayout->addRow(QStringLiteral("Direct Peer"), peerEdit_);
    configLayout->addRow(QStringLiteral("From Address"), fromAddressEdit_);
    configLayout->addRow(QStringLiteral("Transport"), new QLabel(QStringLiteral("Chat signaling -> ECDH session -> AES-GCM frames -> Opus")));
    configLayout->addRow(QString(), obfuscateCheck_);
    lowerLayout->addWidget(configBox);

    auto* actions = new QWidget(lowerPane);
    auto* actionsLayout = new QHBoxLayout(actions);
    actionsLayout->setContentsMargins(0, 0, 0, 0);
    actionsLayout->setSpacing(8);
    startButton_ = new QPushButton(QStringLiteral("Start Call"), lowerPane);
    startButton_->setObjectName(QStringLiteral("forumAccentButton"));
    acceptButton_ = new QPushButton(QStringLiteral("Accept"), lowerPane);
    acceptButton_->setObjectName(QStringLiteral("forumAccentButton"));
    declineButton_ = new QPushButton(QStringLiteral("Decline"), lowerPane);
    declineButton_->setObjectName(QStringLiteral("forumGhostButton"));
    endButton_ = new QPushButton(QStringLiteral("End Call"), lowerPane);
    endButton_->setObjectName(QStringLiteral("forumGhostButton"));
    refreshButton_ = new QPushButton(QStringLiteral("Refresh"), lowerPane);
    refreshButton_->setObjectName(QStringLiteral("forumGhostButton"));
    actionsLayout->addWidget(startButton_);
    actionsLayout->addWidget(acceptButton_);
    actionsLayout->addWidget(declineButton_);
    actionsLayout->addWidget(endButton_);
    actionsLayout->addStretch(1);
    actionsLayout->addWidget(refreshButton_);
    lowerLayout->addWidget(actions);
    mainSplitter->addWidget(lowerPane);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 2);

    stateTimer_ = new QTimer(this);
    stateTimer_->setInterval(1000);
    audioTimer_ = new QTimer(this);
    audioTimer_->setInterval(120);
    clockTimer_ = new QTimer(this);
    clockTimer_->setInterval(1000);

    connect(stateTimer_, &QTimer::timeout, this, [this]() { pollState(); });
    connect(audioTimer_, &QTimer::timeout, this, [this]() { pollIncomingAudio(); });
    connect(clockTimer_, &QTimer::timeout, this, [this]() { updateLiveTimestamp(); });
    connect(startButton_, &QPushButton::clicked, this, [this]() { startCall(); });
    connect(acceptButton_, &QPushButton::clicked, this, [this]() { acceptCall(); });
    connect(declineButton_, &QPushButton::clicked, this, [this]() { declineCall(); });
    connect(endButton_, &QPushButton::clicked, this, [this]() { endCall(); });
    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refresh(); });

    stateTimer_->start();
    audioTimer_->start();
    clockTimer_->start();
    updateControls();
}

void VoiceCallPage::setRpcClient(RpcClient* client) {
    rpc_ = client;
    refresh();
}

void VoiceCallPage::setCallTarget(const QString& address,
                                  const QString& pubkeyB64,
                                  const QString& peer) {
    recipientEdit_->setText(address.trimmed());
    recipientPubkeyEdit_->setText(pubkeyB64.trimmed());
    if (!peer.trimmed().isEmpty()) {
        peerEdit_->setText(peer.trimmed());
    }
    recipientEdit_->setFocus();
}

void VoiceCallPage::refresh() {
    pollState();
}

void VoiceCallPage::setStatus(const QString& text, bool error) {
    statusValue_->setText(text);
    statusValue_->setStyleSheet(error ? chatui::errorColorStyle() : QString());
}

void VoiceCallPage::startCall() {
    if (!rpc_) {
        setStatus(QStringLiteral("RPC client not configured."), true);
        return;
    }
    if (recipientEdit_->text().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Recipient address is required to start a voice call."), true);
        return;
    }
    if (recipientPubkeyEdit_->text().trimmed().isEmpty()) {
        setStatus(QStringLiteral("Recipient pubkey is required for secure voice calls."), true);
        return;
    }

    QJsonObject request;
    request.insert(QStringLiteral("recipient_address"), recipientEdit_->text().trimmed());
    request.insert(QStringLiteral("recipient_pubkey_b64"), recipientPubkeyEdit_->text().trimmed());
    if (!peerEdit_->text().trimmed().isEmpty()) {
        request.insert(QStringLiteral("peer"), peerEdit_->text().trimmed());
    }
    if (!fromAddressEdit_->text().trimmed().isEmpty()) {
        request.insert(QStringLiteral("from_address"), fromAddressEdit_->text().trimmed());
    }
    request.insert(QStringLiteral("obfuscate_audio"), obfuscateCheck_->isChecked());

    setStatus(QStringLiteral("Starting encrypted voice call…"));
    rpc_->call(QStringLiteral("startvoicecall"), QJsonArray{request}, this,
               [this](const QJsonValue& result) {
                   updateUiFromState(result.toObject());
                   setStatus(QStringLiteral("Voice call offer dispatched through the relay network."));
               },
               [this](const QString& error) { setStatus(error, true); });
}

void VoiceCallPage::acceptCall() {
    if (!rpc_) return;
    setStatus(QStringLiteral("Accepting voice call…"));
    rpc_->call(QStringLiteral("acceptvoicecall"), {}, this,
               [this](const QJsonValue& result) {
                   updateUiFromState(result.toObject());
                   setStatus(QStringLiteral("Voice call accepted. Live audio relay is active."));
               },
               [this](const QString& error) { setStatus(error, true); });
}

void VoiceCallPage::declineCall() {
    if (!rpc_) return;
    rpc_->call(QStringLiteral("declinevoicecall"), {}, this,
               [this](const QJsonValue& result) {
                   updateUiFromState(result.toObject());
                   setStatus(QStringLiteral("Voice call declined. No relay state was persisted."));
               },
               [this](const QString& error) { setStatus(error, true); });
}

void VoiceCallPage::endCall() {
    if (!rpc_) return;
    rpc_->call(QStringLiteral("endvoicecall"), {}, this,
               [this](const QJsonValue& result) {
                   updateUiFromState(result.toObject());
                   setStatus(QStringLiteral("Voice call ended and live buffers were cleared."));
               },
               [this](const QString& error) { setStatus(error, true); });
}

void VoiceCallPage::pollState() {
    if (!rpc_ || pollingState_) {
        return;
    }
    pollingState_ = true;
    rpc_->call(QStringLiteral("getvoicecallstate"), {}, this,
               [this](const QJsonValue& result) {
                   pollingState_ = false;
                   updateUiFromState(result.toObject());
               },
               [this](const QString& error) {
                   pollingState_ = false;
                   setStatus(error, true);
               });
}

void VoiceCallPage::pollIncomingAudio() {
    if (!rpc_ || pollingAudio_ || !state_.value(QStringLiteral("active")).toBool() || !state_.value(QStringLiteral("connected")).toBool()) {
        return;
    }
    pollingAudio_ = true;
    rpc_->call(QStringLiteral("pullvoicecallaudio"), QJsonArray{8}, this,
               [this](const QJsonValue& result) {
                   pollingAudio_ = false;
                   const auto rows = result.toArray();
                   for (const auto& row : rows) {
                       queueIncomingFrame(row.toObject());
                   }
               },
               [this](const QString& error) {
                   pollingAudio_ = false;
                   setStatus(error, true);
               });
}

void VoiceCallPage::updateUiFromState(const QJsonObject& state) {
    const QString previousCallId = activeCallId_;
    const bool wasConnected = state_.value(QStringLiteral("connected")).toBool();
    state_ = state;
    const bool active = state_.value(QStringLiteral("active")).toBool();
    activeCallId_ = active ? state_.value(QStringLiteral("call_id")).toString() : QString();

    if (previousCallId != activeCallId_) {
        resetWaveforms();
        captureBuffer_.clear();
    }

    if (!active) {
        callStateValue_->setText(QStringLiteral("Standby"));
        routeValue_->setText(QStringLiteral("No active call"));
        timestampValue_->setText(QStringLiteral("-"));
        ringStateValue_->setText(QStringLiteral("Call state: idle"));
        latencyValue_->setText(QStringLiteral("Latency: -"));
        qualityValue_->setText(QStringLiteral("Quality: standby"));
        securityValue_->setText(QStringLiteral("Security: ECDH session | AES-GCM frames | opus | no call history persisted"));
        if (wasConnected) {
            stopAudioPipeline();
        }
    } else {
        const bool incoming = state_.value(QStringLiteral("incoming")).toBool();
        const bool ringing = state_.value(QStringLiteral("ringing")).toBool();
        const bool connected = state_.value(QStringLiteral("connected")).toBool();
        const QString status = state_.value(QStringLiteral("status")).toString();
        QString headline = connected ? QStringLiteral("Secure Call Connected")
                                     : (incoming && ringing ? QStringLiteral("Incoming Secure Call")
                                                            : QStringLiteral("Secure Call Negotiation"));
        if (!status.isEmpty() && !connected && !(incoming && ringing)) {
            headline += QStringLiteral(" · %1").arg(status);
        }
        callStateValue_->setText(headline);

        const QString route = state_.value(QStringLiteral("call_route")).toString().trimmed();
        routeValue_->setText(route.isEmpty() ? QStringLiteral("Address route is being negotiated live") : route);
        const QString capabilities = state_.value(QStringLiteral("capabilities")).toString();
        securityValue_->setText(QStringLiteral("Security: %1 | Session: %2 | Capabilities: %3 | Voice cloak: %4")
                                    .arg(state_.value(QStringLiteral("encryption")).toString(QStringLiteral("ECDH / AES-GCM / Opus")),
                                         state_.value(QStringLiteral("session_ready")).toBool() ? QStringLiteral("ready") : QStringLiteral("signaling"),
                                         capabilities.isEmpty() ? QStringLiteral("Opus, AES-GCM") : capabilities,
                                         state_.value(QStringLiteral("obfuscate_audio")).toBool() ? QStringLiteral("active") : QStringLiteral("passive")));
        updateLiveTimestamp();
        updateQualityIndicators();
        if (connected) {
            startAudioPipeline();
        } else {
            stopAudioPipeline();
        }
    }

    if (!active || !state_.value(QStringLiteral("incoming")).toBool()) {
        obfuscateCheck_->setChecked(state_.value(QStringLiteral("obfuscate_audio")).toBool() || obfuscateCheck_->isChecked());
    }
    updateControls();
}

void VoiceCallPage::updateControls() {
    const bool active = state_.value(QStringLiteral("active")).toBool();
    const bool incoming = state_.value(QStringLiteral("incoming")).toBool();
    const bool ringing = state_.value(QStringLiteral("ringing")).toBool();
    const bool connected = state_.value(QStringLiteral("connected")).toBool();
    const bool setupEditable = !active;
    recipientEdit_->setEnabled(setupEditable);
    recipientPubkeyEdit_->setEnabled(setupEditable);
    peerEdit_->setEnabled(setupEditable);
    fromAddressEdit_->setEnabled(setupEditable);
    obfuscateCheck_->setEnabled(setupEditable);

    startButton_->setEnabled(rpc_ && !active);
    acceptButton_->setEnabled(rpc_ && active && incoming && ringing && !connected);
    declineButton_->setEnabled(rpc_ && active && incoming && ringing && !connected);
    endButton_->setEnabled(rpc_ && active);
}

void VoiceCallPage::updateLiveTimestamp() {
    if (!state_.value(QStringLiteral("active")).toBool()) {
        timestampValue_->setText(QStringLiteral("-"));
        ringStateValue_->setText(QStringLiteral("Call state: idle"));
        return;
    }
    const quint64 anchor = state_.value(QStringLiteral("connected")).toBool()
        ? static_cast<quint64>(state_.value(QStringLiteral("connected_at")).toInteger())
        : static_cast<quint64>(state_.value(QStringLiteral("started_at")).toInteger());
    const quint64 now = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
    const quint64 elapsed = anchor > 0 && now >= anchor ? (now - anchor) : 0;
    const bool ringing = state_.value(QStringLiteral("ringing")).toBool() && !state_.value(QStringLiteral("connected")).toBool();
    if (ringing) {
        const QString dots = QStringLiteral(".").repeated((ringPhase_++ % 3) + 1);
        ringStateValue_->setText(QStringLiteral("Call state: ringing%1").arg(dots));
    } else if (state_.value(QStringLiteral("connected")).toBool()) {
        ringStateValue_->setText(QStringLiteral("Call state: connected"));
    } else {
        ringStateValue_->setText(QStringLiteral("Call state: negotiating"));
    }
    timestampValue_->setText(QStringLiteral("Live since %1 | elapsed %2")
                                 .arg(formatTimestamp(anchor), formatDuration(elapsed)));
}

void VoiceCallPage::updateQualityIndicators() {
    if (!state_.value(QStringLiteral("active")).toBool()) {
        latencyValue_->setText(QStringLiteral("Latency: -"));
        qualityValue_->setText(QStringLiteral("Quality: standby"));
        return;
    }

    const auto latencyMs = static_cast<quint64>(state_.value(QStringLiteral("latency_ms")).toInteger());
    const auto jitterMs = static_cast<quint64>(state_.value(QStringLiteral("jitter_ms")).toInteger());
    const auto lastAudioAt = static_cast<quint64>(state_.value(QStringLiteral("last_audio_at")).toInteger());
    const auto now = static_cast<quint64>(QDateTime::currentSecsSinceEpoch());
    const auto freshnessSec = lastAudioAt > 0 && now >= lastAudioAt ? (now - lastAudioAt) : 0;

    if (latencyMs > 0) {
        latencyValue_->setText(QStringLiteral("Latency: ~%1 ms | jitter %2 ms").arg(latencyMs).arg(jitterMs));
    } else {
        latencyValue_->setText(QStringLiteral("Latency: estimating…"));
    }

    QString quality = QStringLiteral("negotiating");
    if (state_.value(QStringLiteral("connected")).toBool()) {
        if (freshnessSec > 3 || latencyMs > 700 || jitterMs > 240) {
            quality = QStringLiteral("degraded");
        } else if (freshnessSec > 1 || latencyMs > 320 || jitterMs > 120 || audioSendInFlight_ > 2) {
            quality = QStringLiteral("fair");
        } else if (latencyMs > 180 || jitterMs > 60) {
            quality = QStringLiteral("good");
        } else {
            quality = QStringLiteral("excellent");
        }
    } else if (state_.value(QStringLiteral("ringing")).toBool()) {
        quality = QStringLiteral("ringing");
    }
    qualityValue_->setText(QStringLiteral("Quality: %1").arg(quality));
}

void VoiceCallPage::startAudioPipeline() {
    if (!state_.value(QStringLiteral("active")).toBool() || !state_.value(QStringLiteral("connected")).toBool()) {
        return;
    }

    const auto inputDevice = QMediaDevices::defaultAudioInput();
    const auto outputDevice = QMediaDevices::defaultAudioOutput();
    if (inputDevice.isNull() || outputDevice.isNull()) {
        setStatus(QStringLiteral("Audio devices are unavailable for live voice relay."), true);
        return;
    }

    const auto desired = chooseSharedFormat(inputDevice,
                                            outputDevice,
                                            static_cast<int>(state_.value(QStringLiteral("sample_rate")).toInteger(16000)),
                                            static_cast<int>(state_.value(QStringLiteral("channels")).toInteger(1)),
                                            static_cast<int>(state_.value(QStringLiteral("bits_per_sample")).toInteger(16)));
    if (desired.sampleFormat() != QAudioFormat::Int16) {
        setStatus(QStringLiteral("Live voice relay currently requires a shared 16-bit PCM device format."), true);
        return;
    }

    const bool sameFormats = audioSource_ && audioSink_ &&
                             captureFormat_.sampleRate() == desired.sampleRate() &&
                             captureFormat_.channelCount() == desired.channelCount() &&
                             captureFormat_.sampleFormat() == desired.sampleFormat() &&
                             playbackFormat_.sampleRate() == desired.sampleRate() &&
                             playbackFormat_.channelCount() == desired.channelCount() &&
                             playbackFormat_.sampleFormat() == desired.sampleFormat();
    if (sameFormats) {
        return;
    }

    stopAudioPipeline();
    captureFormat_ = desired;
    playbackFormat_ = desired;

    auto* playbackBuffer = new PlaybackBufferDevice(this);
    playbackDevice_ = playbackBuffer;
    audioSink_ = new QAudioSink(outputDevice, playbackFormat_, this);
    audioSink_->start(playbackDevice_);

    audioSource_ = new QAudioSource(inputDevice, captureFormat_, this);
    captureDevice_ = audioSource_->start();
    if (captureDevice_) {
        connect(captureDevice_, &QIODevice::readyRead, this, [this]() { processCapturedAudio(); });
    }
}

void VoiceCallPage::stopAudioPipeline() {
    captureBuffer_.clear();
    audioSendInFlight_ = 0;
    if (audioSource_) {
        audioSource_->stop();
        audioSource_->deleteLater();
        audioSource_ = nullptr;
    }
    captureDevice_ = nullptr;
    if (audioSink_) {
        audioSink_->stop();
        audioSink_->deleteLater();
        audioSink_ = nullptr;
    }
    if (auto* playbackBuffer = dynamic_cast<PlaybackBufferDevice*>(playbackDevice_)) {
        playbackBuffer->clear();
    }
    if (playbackDevice_) {
        playbackDevice_->deleteLater();
        playbackDevice_ = nullptr;
    }
}

void VoiceCallPage::processCapturedAudio() {
    if (!captureDevice_ || !rpc_ || !state_.value(QStringLiteral("active")).toBool() || !state_.value(QStringLiteral("connected")).toBool()) {
        return;
    }
    captureBuffer_.append(captureDevice_->readAll());
    const int frameBytes = bytesPerFrame(captureFormat_);
    if (frameBytes <= 0) {
        return;
    }
    const int frameDurationMs = std::max(10, state_.value(QStringLiteral("frame_duration_ms")).toInt(20));
    const int chunkFrames = std::max(1, (captureFormat_.sampleRate() * frameDurationMs) / 1000);
    const int chunkBytes = chunkFrames * frameBytes;
    if (captureBuffer_.size() > chunkBytes * 6) {
        captureBuffer_.remove(0, captureBuffer_.size() - (chunkBytes * 6));
    }

    while (captureBuffer_.size() >= chunkBytes && audioSendInFlight_ < 3) {
        QByteArray chunk = captureBuffer_.left(chunkBytes);
        captureBuffer_.remove(0, chunkBytes);
        const bool obfuscate = state_.value(QStringLiteral("obfuscate_audio")).toBool();
        const QByteArray previewChunk = obfuscate ? obfuscatePcm16Chunk(chunk, captureFormat_.channelCount()) : chunk;
        if (obfuscate) {
            if (auto* waveform = static_cast<VoiceWaveformView*>(waveformView_)) {
                waveform->setOutgoingLevels(levelsFromPcm16(previewChunk, captureFormat_.channelCount()));
            }
        } else if (auto* waveform = static_cast<VoiceWaveformView*>(waveformView_)) {
            waveform->setOutgoingLevels(levelsFromPcm16(chunk, captureFormat_.channelCount()));
        }
        QJsonObject request;
        request.insert(QStringLiteral("audio_b64"), QString::fromLatin1(chunk.toBase64()));
        request.insert(QStringLiteral("sample_rate"), captureFormat_.sampleRate());
        request.insert(QStringLiteral("channels"), captureFormat_.channelCount());
        request.insert(QStringLiteral("bits_per_sample"), captureFormat_.bytesPerSample() * 8);
        request.insert(QStringLiteral("obfuscated"), obfuscate);
        ++audioSendInFlight_;
        rpc_->call(QStringLiteral("sendvoicecallaudio"), QJsonArray{request}, this,
                   [this](const QJsonValue&) {
                       audioSendInFlight_ = std::max(0, audioSendInFlight_ - 1);
                       updateQualityIndicators();
                   },
                   [this](const QString& error) {
                       audioSendInFlight_ = std::max(0, audioSendInFlight_ - 1);
                       setStatus(error, true);
                       updateQualityIndicators();
                   });
    }
}

void VoiceCallPage::queueIncomingFrame(const QJsonObject& frame) {
    const auto audioB64 = frame.value(QStringLiteral("audio_b64")).toString();
    if (audioB64.isEmpty()) {
        return;
    }
    const QByteArray pcm = QByteArray::fromBase64(audioB64.toLatin1());
    if (pcm.isEmpty()) {
        return;
    }
    if (auto* playbackBuffer = dynamic_cast<PlaybackBufferDevice*>(playbackDevice_)) {
        playbackBuffer->enqueue(pcm);
    }
    if (auto* waveform = static_cast<VoiceWaveformView*>(waveformView_)) {
        waveform->setIncomingLevels(levelsFromPcm16(pcm, frame.value(QStringLiteral("channels")).toInt(1)));
    }
    updateQualityIndicators();
}

void VoiceCallPage::resetWaveforms() {
    if (auto* waveform = static_cast<VoiceWaveformView*>(waveformView_)) {
        waveform->clearLevels();
    }
}

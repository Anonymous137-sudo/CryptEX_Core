#include "DaemonController.hpp"

#include <QStringList>
#include <QFileInfo>

namespace {

void emit_complete_lines(QString& buffer, bool error, DaemonController* self) {
    while (true) {
        const int newline = buffer.indexOf('\n');
        if (newline < 0) {
            break;
        }
        QString line = buffer.left(newline);
        if (!line.isEmpty() && line.endsWith('\r')) {
            line.chop(1);
        }
        buffer.remove(0, newline + 1);
        if (line.isEmpty()) {
            continue;
        }
        if (error) emit self->errorLine(line);
        else emit self->outputLine(line);
    }
}

}

DaemonController::DaemonController(QObject* parent)
    : QObject(parent) {
    process_.setProcessChannelMode(QProcess::MergedChannels);
    connect(&process_, &QProcess::readyReadStandardOutput, this, [this]() {
        stdoutBuffer_ += QString::fromUtf8(process_.readAllStandardOutput());
        flushBufferedLines(stdoutBuffer_, false);
    });
    connect(&process_, &QProcess::readyReadStandardError, this, [this]() {
        stderrBuffer_ += QString::fromUtf8(process_.readAllStandardError());
        flushBufferedLines(stderrBuffer_, true);
    });
    connect(&process_, &QProcess::stateChanged, this, [this](QProcess::ProcessState state) {
        emit stateChanged(state != QProcess::NotRunning);
    });
    connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
        [this](int, QProcess::ExitStatus) {
            if (!stdoutBuffer_.isEmpty()) {
                emit outputLine(stdoutBuffer_);
                stdoutBuffer_.clear();
            }
            if (!stderrBuffer_.isEmpty()) {
                emit errorLine(stderrBuffer_);
                stderrBuffer_.clear();
            }
        });
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        switch (error) {
        case QProcess::FailedToStart:
            emit errorLine(QStringLiteral("Failed to start backend process."));
            break;
        case QProcess::Crashed:
            emit errorLine(QStringLiteral("Backend process crashed."));
            break;
        default:
            emit errorLine(process_.errorString());
            break;
        }
    });
}

bool DaemonController::isRunning() const {
    return process_.state() != QProcess::NotRunning;
}

void DaemonController::startNode(const LaunchConfig& config) {
    if (config.executablePath.isEmpty()) {
        emit errorLine(QStringLiteral("Backend binary path is empty."));
        return;
    }
    if (!QFileInfo::exists(config.executablePath)) {
        emit errorLine(QStringLiteral("Backend binary was not found at: ") + config.executablePath);
        return;
    }

    if (isRunning()) {
        stopNode();
    }

    QStringList args;
    if (config.network == QStringLiteral("testnet")) args << "--testnet";
    else if (config.network == QStringLiteral("regtest")) args << "--regtest";
    else args << "--mainnet";

    args << "node";
    if (!config.dataDir.isEmpty()) args << "--datadir" << config.dataDir;
    if (!config.rpcBind.isEmpty()) args << "--rpcbind" << config.rpcBind;
    if (config.rpcPort > 0) args << "--rpcport" << QString::number(config.rpcPort);
    if (!config.rpcUser.isEmpty()) args << "--rpcuser" << config.rpcUser;
    if (!config.rpcPassword.isEmpty()) args << "--rpcpassword" << config.rpcPassword;
    if (!config.walletPath.isEmpty()) args << "--wallet" << config.walletPath;
    if (!config.walletPassword.isEmpty()) args << "--walletpass" << config.walletPassword;
    if (config.debug) args << "--debug";

    process_.start(config.executablePath, args);
}

void DaemonController::stopNode() {
    if (!isRunning()) return;
    process_.terminate();
    if (!process_.waitForFinished(3000)) {
        process_.kill();
        process_.waitForFinished(2000);
    }
}

void DaemonController::flushBufferedLines(QString& buffer, bool error) {
    emit_complete_lines(buffer, error, this);
}

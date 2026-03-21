#include "MinerController.hpp"

#include <QStringList>

namespace {

void emit_complete_lines(QString& buffer, bool error, MinerController* self) {
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

MinerController::MinerController(QObject* parent)
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
}

bool MinerController::isRunning() const {
    return process_.state() != QProcess::NotRunning;
}

void MinerController::startMining(const LaunchConfig& config) {
    if (config.executablePath.isEmpty()) {
        emit errorLine(QStringLiteral("Miner binary path is empty."));
        return;
    }
    if (config.rewardAddress.trimmed().isEmpty()) {
        emit errorLine(QStringLiteral("Reward address is required."));
        return;
    }

    if (isRunning()) {
        stopMining();
    }

    QStringList args;
    if (config.network == QStringLiteral("testnet")) args << "--testnet";
    else if (config.network == QStringLiteral("regtest")) args << "--regtest";
    else args << "--mainnet";

    args << "mine";
    args << "--address" << config.rewardAddress.trimmed();
    args << "--cycles" << QString::number(config.cycles);
    args << "--block-cycles" << QString::number(config.blockCycles);
    args << "--threads" << QString::number(config.threads);
    args << "--sync-wait-ms" << QString::number(config.syncWaitMs);
    if (!config.dataDir.trimmed().isEmpty()) args << "--datadir" << config.dataDir.trimmed();
    if (!config.connectEndpoint.trimmed().isEmpty()) args << "--connect" << config.connectEndpoint.trimmed();
    if (config.debug) args << "--debug";

    process_.start(config.executablePath, args);
}

void MinerController::stopMining() {
    if (!isRunning()) return;
    process_.terminate();
    if (!process_.waitForFinished(3000)) {
        process_.kill();
        process_.waitForFinished(2000);
    }
}

void MinerController::flushBufferedLines(QString& buffer, bool error) {
    emit_complete_lines(buffer, error, this);
}

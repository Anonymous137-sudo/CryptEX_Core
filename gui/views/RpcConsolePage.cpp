#include "RpcConsolePage.hpp"
#include "rpc/RpcClient.hpp"

#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

QString timestampPrefix() {
    return QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"));
}

}

RpcConsolePage::RpcConsolePage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    setStyleSheet(
        "QGroupBox { background: #0a0a0a; border: 1px solid #1e4f23; border-radius: 4px; margin-top: 14px; "
        "padding-top: 14px; color: #63ff7d; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; color: #63ff7d; }"
        "QLabel { color: #63ff7d; }"
        "QLineEdit, QPlainTextEdit { background: #050505; color: #63ff7d; border: 1px solid #1e4f23; "
        "border-radius: 3px; selection-background-color: #1e4f23; font-family: Menlo, Monaco, monospace; }"
        "QPushButton { background: #112914; color: #8bff9f; border: 1px solid #1e4f23; border-radius: 4px; padding: 5px 12px; }"
        "QPushButton:hover { background: #16361a; }"
        "QPushButton:pressed { background: #0d2210; }");

    auto* title = new QLabel(QStringLiteral("RPC Console"));
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    auto* inputBox = new QGroupBox(QStringLiteral("Command"), this);
    auto* inputLayout = new QFormLayout(inputBox);
    inputLayout->setHorizontalSpacing(18);
    inputLayout->setVerticalSpacing(10);

    methodEdit_ = new QLineEdit(this);
    methodEdit_->setPlaceholderText(QStringLiteral("Example: getblockchaininfo"));

    paramsEdit_ = new QPlainTextEdit(this);
    paramsEdit_->setPlaceholderText(QStringLiteral("JSON array parameters, for example:\n[]\n[1]\n[\"0000...\"]"));
    paramsEdit_->setFixedHeight(90);

    auto* buttonRow = new QWidget(this);
    auto* buttonLayout = new QHBoxLayout(buttonRow);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(8);
    executeButton_ = new QPushButton(QStringLiteral("Execute"), this);
    clearButton_ = new QPushButton(QStringLiteral("Clear Console"), this);
    buttonLayout->addWidget(executeButton_);
    buttonLayout->addWidget(clearButton_);
    buttonLayout->addStretch(1);

    inputLayout->addRow(QStringLiteral("Method"), methodEdit_);
    inputLayout->addRow(QStringLiteral("Params"), paramsEdit_);
    inputLayout->addRow(QString(), buttonRow);
    root->addWidget(inputBox);

    auto* transcriptBox = new QGroupBox(QStringLiteral("Output"), this);
    auto* transcriptLayout = new QVBoxLayout(transcriptBox);
    transcriptView_ = new QPlainTextEdit(this);
    transcriptView_->setReadOnly(true);
    transcriptView_->setPlaceholderText(QStringLiteral("RPC responses will appear here."));
    transcriptView_->setStyleSheet(
        "QPlainTextEdit { background: #000000; color: #5dff74; border: 1px solid #1e4f23; "
        "font-family: Menlo, Monaco, monospace; font-size: 12px; selection-background-color: #1e4f23; }");
    transcriptLayout->addWidget(transcriptView_);
    root->addWidget(transcriptBox, 1);

    connect(executeButton_, &QPushButton::clicked, this, [this]() { executeCommand(); });
    connect(clearButton_, &QPushButton::clicked, transcriptView_, &QPlainTextEdit::clear);
    connect(methodEdit_, &QLineEdit::returnPressed, this, [this]() { executeCommand(); });
}

void RpcConsolePage::setRpcClient(RpcClient* client) {
    rpc_ = client;
}

void RpcConsolePage::executeCommand() {
    if (!rpc_) {
        appendTranscript(QStringLiteral("[error] RPC client not configured."));
        return;
    }

    const auto method = methodEdit_->text().trimmed();
    if (method.isEmpty()) {
        appendTranscript(QStringLiteral("[error] Enter an RPC method name."));
        return;
    }

    const auto paramsText = paramsEdit_->toPlainText().trimmed();
    QJsonArray params;
    if (!paramsText.isEmpty()) {
        QJsonParseError parseError;
        const auto doc = QJsonDocument::fromJson(paramsText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isArray()) {
            appendTranscript(QStringLiteral("[error] Params must be a valid JSON array."));
            return;
        }
        params = doc.array();
    }

    appendTranscript(QStringLiteral(">> %1 %2").arg(method, paramsText.isEmpty() ? QStringLiteral("[]") : paramsText));
    rpc_->call(method, params, this,
        [this](const QJsonValue& result) {
            appendTranscript(stringifyJsonValue(result));
        },
        [this](const QString& error) {
            appendTranscript(QStringLiteral("[error] %1").arg(error));
        });
}

void RpcConsolePage::appendTranscript(const QString& line) {
    transcriptView_->appendPlainText(QStringLiteral("[%1] %2").arg(timestampPrefix(), line));
}

QString RpcConsolePage::stringifyJsonValue(const QJsonValue& value) const {
    if (value.isObject()) {
        return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Indented)).trimmed();
    }
    if (value.isArray()) {
        return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Indented)).trimmed();
    }
    if (value.isString()) return value.toString();
    if (value.isBool()) return value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    if (value.isDouble()) return QString::number(value.toDouble(), 'g', 16);
    if (value.isNull() || value.isUndefined()) return QStringLiteral("null");
    return QStringLiteral("<unprintable>");
}

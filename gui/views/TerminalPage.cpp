#include "TerminalPage.hpp"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QTextCursor>
#include <QVBoxLayout>

namespace {

QString timestampTag() {
    return QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"));
}

}

TerminalPage::TerminalPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(12);

    setStyleSheet(
        "QLabel { color: #63ff7d; }"
        "QLineEdit, QPlainTextEdit { background: #050505; color: #63ff7d; border: 1px solid #1e4f23; "
        "border-radius: 3px; selection-background-color: #1e4f23; font-family: Menlo, Monaco, monospace; }"
        "QPushButton { background: #112914; color: #8bff9f; border: 1px solid #1e4f23; border-radius: 4px; padding: 5px 12px; }"
        "QPushButton:hover { background: #16361a; }"
        "QPushButton:pressed { background: #0d2210; }");

    auto* title = new QLabel(QStringLiteral("System Terminal"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    shellInfoLabel_ = new QLabel(this);
    shellInfoLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(shellInfoLabel_);

    statusLabel_ = new QLabel(QStringLiteral("Preparing shell..."), this);
    statusLabel_->setWordWrap(true);
    root->addWidget(statusLabel_);

    outputView_ = new QPlainTextEdit(this);
    outputView_->setReadOnly(true);
    outputView_->setPlaceholderText(QStringLiteral("Shell output will appear here."));
    outputView_->setStyleSheet(
        "QPlainTextEdit { background: #000000; color: #5dff74; border: 1px solid #1e4f23; "
        "font-family: Menlo, Monaco, monospace; font-size: 12px; selection-background-color: #1e4f23; }");
    root->addWidget(outputView_, 1);

    auto* inputRow = new QHBoxLayout();
    inputRow->setSpacing(8);
    commandEdit_ = new QLineEdit(this);
    commandEdit_->setPlaceholderText(QStringLiteral("Enter a command and press Run or Enter"));
    runButton_ = new QPushButton(QStringLiteral("Run"), this);
    restartButton_ = new QPushButton(QStringLiteral("Restart Shell"), this);
    clearButton_ = new QPushButton(QStringLiteral("Clear"), this);
    inputRow->addWidget(commandEdit_, 1);
    inputRow->addWidget(runButton_);
    inputRow->addWidget(restartButton_);
    inputRow->addWidget(clearButton_);
    root->addLayout(inputRow);

    process_.setProcessChannelMode(QProcess::MergedChannels);
    process_.setWorkingDirectory(QDir::homePath());

    connect(&process_, &QProcess::started, this, [this]() {
        shellInfoLabel_->setText(QStringLiteral("Shell: %1 | Working directory: %2")
            .arg(shellDisplayName(), process_.workingDirectory()));
        statusLabel_->setText(QStringLiteral("Shell ready."));
        appendOutput(QStringLiteral("[%1] shell started: %2").arg(timestampTag(), shellDisplayName()));
    });
    connect(&process_, &QProcess::readyReadStandardOutput, this, [this]() {
        appendOutput(QString::fromUtf8(process_.readAllStandardOutput()));
    });
    connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
        [this](int exitCode, QProcess::ExitStatus) {
            statusLabel_->setText(QStringLiteral("Shell stopped with exit code %1.").arg(exitCode));
            appendOutput(QStringLiteral("\n[%1] shell stopped with exit code %2\n").arg(timestampTag()).arg(exitCode));
        });
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        statusLabel_->setText(QStringLiteral("Shell error: %1").arg(process_.errorString()));
        appendOutput(QStringLiteral("\n[%1] shell error: %2\n").arg(timestampTag(), process_.errorString()));
    });

    connect(runButton_, &QPushButton::clicked, this, [this]() { sendCommand(); });
    connect(restartButton_, &QPushButton::clicked, this, [this]() {
        stopShell();
        startShell();
    });
    connect(clearButton_, &QPushButton::clicked, outputView_, &QPlainTextEdit::clear);
    connect(commandEdit_, &QLineEdit::returnPressed, this, [this]() { sendCommand(); });

    startShell();
}

TerminalPage::~TerminalPage() {
    stopShell();
}

void TerminalPage::startShell() {
    if (process_.state() != QProcess::NotRunning) {
        return;
    }

    const auto program = shellProgram();
    if (program.isEmpty()) {
        statusLabel_->setText(QStringLiteral("No shell program found for this platform."));
        return;
    }

    shellInfoLabel_->setText(QStringLiteral("Shell: %1 | Working directory: %2")
        .arg(shellDisplayName(), process_.workingDirectory()));
    statusLabel_->setText(QStringLiteral("Starting %1...").arg(shellDisplayName()));
    process_.start(program, shellArguments());
}

void TerminalPage::stopShell() {
    if (process_.state() == QProcess::NotRunning) {
        return;
    }
    process_.terminate();
    if (!process_.waitForFinished(1500)) {
        process_.kill();
        process_.waitForFinished(1500);
    }
}

void TerminalPage::sendCommand() {
    const auto command = commandEdit_->text().trimmed();
    if (command.isEmpty()) {
        return;
    }
    if (process_.state() == QProcess::NotRunning) {
        startShell();
        if (process_.state() == QProcess::NotRunning) {
            statusLabel_->setText(QStringLiteral("Shell is not running."));
            return;
        }
    }

    appendOutput(QStringLiteral("\n[%1] %2 %3\n").arg(timestampTag(), commandPrompt(), command));
    process_.write(command.toUtf8());
    process_.write("\n");
    commandEdit_->clear();
}

void TerminalPage::appendOutput(const QString& text) {
    if (text.isEmpty()) {
        return;
    }
    outputView_->moveCursor(QTextCursor::End);
    outputView_->insertPlainText(text);
    auto* scroll = outputView_->verticalScrollBar();
    scroll->setValue(scroll->maximum());
}

QString TerminalPage::shellProgram() const {
#ifdef Q_OS_WIN
    return QStringLiteral("cmd.exe");
#elif defined(Q_OS_MACOS)
    if (QFileInfo::exists(QStringLiteral("/bin/zsh"))) {
        return QStringLiteral("/bin/zsh");
    }
    return QStringLiteral("/bin/bash");
#else
    if (QFileInfo::exists(QStringLiteral("/bin/bash"))) {
        return QStringLiteral("/bin/bash");
    }
    return QStringLiteral("/bin/sh");
#endif
}

QStringList TerminalPage::shellArguments() const {
#ifdef Q_OS_WIN
    return {QStringLiteral("/Q"), QStringLiteral("/K")};
#else
    return {};
#endif
}

QString TerminalPage::shellDisplayName() const {
    return QFileInfo(shellProgram()).fileName();
}

QString TerminalPage::commandPrompt() const {
#ifdef Q_OS_WIN
    return QStringLiteral(">");
#else
    return QStringLiteral("$");
#endif
}

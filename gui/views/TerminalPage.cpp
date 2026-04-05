#include "TerminalPage.hpp"

#include <QCheckBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QScrollBar>
#include <QTabBar>
#include <QTabWidget>
#include <QTextCursor>
#include <QVBoxLayout>

namespace {

QString timestampTag() {
    return QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"));
}

QString shellProgramForPlatform() {
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

QStringList shellArgumentsForPlatform() {
#ifdef Q_OS_WIN
    return {QStringLiteral("/Q"), QStringLiteral("/K")};
#else
    return {QStringLiteral("-i")};
#endif
}

QString shellDisplayNameForPlatform() {
    return QFileInfo(shellProgramForPlatform()).fileName();
}

QString commandPromptForPlatform() {
#ifdef Q_OS_WIN
    return QStringLiteral(">");
#else
    return QStringLiteral("$");
#endif
}

QString sessionTitleForIndex(int index) {
    return QStringLiteral("Tab %1").arg(index + 1);
}

class ShellSessionWidget final : public QWidget {
public:
    explicit ShellSessionWidget(bool followOutput, QWidget* parent = nullptr)
        : QWidget(parent) {
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(0, 0, 0, 0);
        root->setSpacing(8);

        auto* infoRow = new QHBoxLayout();
        infoRow->setSpacing(12);
        shellInfoLabel_ = new QLabel(this);
        shellInfoLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        workingDirLabel_ = new QLabel(this);
        workingDirLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        infoRow->addWidget(shellInfoLabel_, 1);
        infoRow->addWidget(workingDirLabel_, 1);
        root->addLayout(infoRow);

        statusLabel_ = new QLabel(QStringLiteral("Preparing shell session..."), this);
        statusLabel_->setWordWrap(true);
        root->addWidget(statusLabel_);

        outputView_ = new QPlainTextEdit(this);
        outputView_->setReadOnly(true);
        outputView_->setUndoRedoEnabled(false);
        outputView_->setMaximumBlockCount(5000);
        outputView_->setPlaceholderText(QStringLiteral("Interactive shell output will appear here."));
        outputView_->setStyleSheet(
            "QPlainTextEdit { background: #000000; color: #63ff7d; border: 1px solid #1e4f23; "
            "font-family: Menlo, Monaco, 'Cascadia Mono', monospace; font-size: 12px; "
            "selection-background-color: #1e4f23; }");
        root->addWidget(outputView_, 1);

        auto* inputRow = new QHBoxLayout();
        inputRow->setSpacing(8);
        promptLabel_ = new QLabel(commandPromptForPlatform(), this);
        promptLabel_->setStyleSheet(QStringLiteral("QLabel { color: #8bff9f; font-family: Menlo, Monaco, monospace; }"));
        commandEdit_ = new QLineEdit(this);
        commandEdit_->setPlaceholderText(QStringLiteral("Type a command, press Enter to run, and use Up/Down for history"));
        commandEdit_->setStyleSheet(
            "QLineEdit { background: #050505; color: #63ff7d; border: 1px solid #1e4f23; "
            "border-radius: 3px; padding: 4px 6px; font-family: Menlo, Monaco, 'Cascadia Mono', monospace; }");
        runButton_ = new QPushButton(QStringLiteral("Run"), this);
        runButton_->setStyleSheet(
            "QPushButton { background: #112914; color: #8bff9f; border: 1px solid #1e4f23; border-radius: 4px; padding: 5px 12px; }"
            "QPushButton:hover { background: #16361a; }"
            "QPushButton:pressed { background: #0d2210; }");
        inputRow->addWidget(promptLabel_);
        inputRow->addWidget(commandEdit_, 1);
        inputRow->addWidget(runButton_);
        root->addLayout(inputRow);

        commandEdit_->installEventFilter(this);

        process_.setProcessChannelMode(QProcess::MergedChannels);
        process_.setWorkingDirectory(QDir::homePath());

        connect(&process_, &QProcess::started, this, [this]() {
            shellInfoLabel_->setText(QStringLiteral("Shell: %1").arg(shellDisplayNameForPlatform()));
            workingDirLabel_->setText(QStringLiteral("Start directory: %1").arg(process_.workingDirectory()));
            statusLabel_->setText(QStringLiteral("Shell ready."));
            appendOutput(QStringLiteral("[%1] shell started: %2\n")
                             .arg(timestampTag(), shellDisplayNameForPlatform()));
        });
        connect(&process_, &QProcess::readyReadStandardOutput, this, [this]() {
            appendOutput(QString::fromUtf8(process_.readAllStandardOutput()));
        });
        connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int exitCode, QProcess::ExitStatus) {
                    statusLabel_->setText(QStringLiteral("Shell stopped with exit code %1.").arg(exitCode));
                    appendOutput(QStringLiteral("\n[%1] shell stopped with exit code %2\n")
                                     .arg(timestampTag())
                                     .arg(exitCode));
                });
        connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
            statusLabel_->setText(QStringLiteral("Shell error: %1").arg(process_.errorString()));
            appendOutput(QStringLiteral("\n[%1] shell error: %2\n")
                             .arg(timestampTag(), process_.errorString()));
        });
        connect(runButton_, &QPushButton::clicked, this, [this]() { sendCurrentCommand(); });
        connect(commandEdit_, &QLineEdit::returnPressed, this, [this]() { sendCurrentCommand(); });

        setFollowOutput(followOutput);
        startShell();
    }

    ~ShellSessionWidget() override {
        stopShell();
    }

    void setFollowOutput(bool enabled) {
        followOutput_ = enabled;
    }

    void restartShell() {
        stopShell();
        startShell();
    }

    void stopShell() {
        if (process_.state() == QProcess::NotRunning) {
            return;
        }
        process_.terminate();
        if (!process_.waitForFinished(1500)) {
            process_.kill();
            process_.waitForFinished(1500);
        }
    }

    void clearOutput() {
        outputView_->clear();
        appendOutput(QStringLiteral("[%1] terminal cleared\n").arg(timestampTag()));
    }

    QString statusText() const {
        return statusLabel_ ? statusLabel_->text() : QString();
    }

    QString shellInfoText() const {
        return shellInfoLabel_ ? shellInfoLabel_->text() : QString();
    }

    QString workingDirText() const {
        return workingDirLabel_ ? workingDirLabel_->text() : QString();
    }

    bool isRunning() const {
        return process_.state() != QProcess::NotRunning;
    }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        if (watched == commandEdit_ && event->type() == QEvent::KeyPress) {
            auto* keyEvent = static_cast<QKeyEvent*>(event);
            if (keyEvent->key() == Qt::Key_Up) {
                navigateHistory(-1);
                return true;
            }
            if (keyEvent->key() == Qt::Key_Down) {
                navigateHistory(1);
                return true;
            }
        }
        return QWidget::eventFilter(watched, event);
    }

private:
    void startShell() {
        if (process_.state() != QProcess::NotRunning) {
            return;
        }

        const auto program = shellProgramForPlatform();
        if (program.isEmpty()) {
            statusLabel_->setText(QStringLiteral("No shell program found for this platform."));
            return;
        }

        shellInfoLabel_->setText(QStringLiteral("Shell: %1").arg(shellDisplayNameForPlatform()));
        workingDirLabel_->setText(QStringLiteral("Start directory: %1").arg(process_.workingDirectory()));
        statusLabel_->setText(QStringLiteral("Starting %1...").arg(shellDisplayNameForPlatform()));
        process_.start(program, shellArgumentsForPlatform());
    }

    void appendOutput(const QString& text) {
        if (text.isEmpty()) {
            return;
        }
        outputView_->moveCursor(QTextCursor::End);
        outputView_->insertPlainText(text);
        if (followOutput_) {
            auto* scroll = outputView_->verticalScrollBar();
            scroll->setValue(scroll->maximum());
        }
    }

    void sendCurrentCommand() {
        const auto command = commandEdit_->text();
        if (command.trimmed().isEmpty()) {
            return;
        }
        if (process_.state() == QProcess::NotRunning) {
            startShell();
            if (process_.state() == QProcess::NotRunning) {
                statusLabel_->setText(QStringLiteral("Shell is not running."));
                return;
            }
        }

        if (history_.isEmpty() || history_.back() != command) {
            history_.append(command);
        }
        historyIndex_ = history_.size();
        historyDraft_.clear();

        appendOutput(QStringLiteral("\n[%1] %2 %3\n")
                         .arg(timestampTag(), commandPromptForPlatform(), command));
        process_.write(command.toUtf8());
        process_.write("\n");
        commandEdit_->clear();
    }

    void navigateHistory(int delta) {
        if (history_.isEmpty()) {
            return;
        }

        if (historyIndex_ == history_.size()) {
            historyDraft_ = commandEdit_->text();
        }

        historyIndex_ += delta;
        historyIndex_ = qBound(0, historyIndex_, history_.size());

        if (historyIndex_ == history_.size()) {
            commandEdit_->setText(historyDraft_);
            return;
        }

        commandEdit_->setText(history_.at(historyIndex_));
    }

    QLabel* shellInfoLabel_{nullptr};
    QLabel* workingDirLabel_{nullptr};
    QLabel* statusLabel_{nullptr};
    QLabel* promptLabel_{nullptr};
    QPlainTextEdit* outputView_{nullptr};
    QLineEdit* commandEdit_{nullptr};
    QPushButton* runButton_{nullptr};
    QProcess process_;
    QStringList history_;
    int historyIndex_{0};
    QString historyDraft_;
    bool followOutput_{true};
};

ShellSessionWidget* asSession(QWidget* widget) {
    return dynamic_cast<ShellSessionWidget*>(widget);
}

} // namespace

TerminalPage::TerminalPage(QWidget* parent)
    : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    setStyleSheet(
        "QLabel { color: #63ff7d; }"
        "QCheckBox { color: #8bff9f; }"
        "QTabWidget::pane { border: 1px solid #1e4f23; background: #040404; }"
        "QTabBar::tab { background: #0a150b; color: #7bf18f; border: 1px solid #1e4f23; padding: 6px 12px; min-width: 90px; }"
        "QTabBar::tab:selected { background: #132d15; color: #c7ffd1; }"
        "QTabBar::tab:hover { background: #16361a; }"
        "QPushButton { background: #112914; color: #8bff9f; border: 1px solid #1e4f23; border-radius: 4px; padding: 5px 12px; }"
        "QPushButton:hover { background: #16361a; }"
        "QPushButton:pressed { background: #0d2210; }");

    auto* title = new QLabel(QStringLiteral("System Terminal"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    root->addWidget(title);

    shellInfoLabel_ = new QLabel(QStringLiteral("Preparing terminal workspace..."), this);
    shellInfoLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(shellInfoLabel_);

    statusLabel_ = new QLabel(QStringLiteral("Each tab has its own %1 shell session with scrollback and command history.")
                                  .arg(shellDisplayNameForPlatform()),
                              this);
    statusLabel_->setWordWrap(true);
    root->addWidget(statusLabel_);

    auto* toolbar = new QHBoxLayout();
    toolbar->setSpacing(8);
    newTabButton_ = new QPushButton(QStringLiteral("New Tab"), this);
    closeTabButton_ = new QPushButton(QStringLiteral("Close Tab"), this);
    restartTabButton_ = new QPushButton(QStringLiteral("Restart Tab"), this);
    stopTabButton_ = new QPushButton(QStringLiteral("Stop Tab"), this);
    clearTabButton_ = new QPushButton(QStringLiteral("Clear Output"), this);
    followOutputCheck_ = new QCheckBox(QStringLiteral("Follow output"), this);
    followOutputCheck_->setChecked(true);
    toolbar->addWidget(newTabButton_);
    toolbar->addWidget(closeTabButton_);
    toolbar->addWidget(restartTabButton_);
    toolbar->addWidget(stopTabButton_);
    toolbar->addWidget(clearTabButton_);
    toolbar->addStretch(1);
    toolbar->addWidget(followOutputCheck_);
    root->addLayout(toolbar);

    tabWidget_ = new QTabWidget(this);
    tabWidget_->setDocumentMode(true);
    tabWidget_->setMovable(true);
    tabWidget_->setTabsClosable(true);
    tabWidget_->tabBar()->setElideMode(Qt::ElideRight);
    root->addWidget(tabWidget_, 1);

    connect(newTabButton_, &QPushButton::clicked, this, [this]() { addTerminalTab(); });
    connect(closeTabButton_, &QPushButton::clicked, this, [this]() { closeCurrentTab(); });
    connect(restartTabButton_, &QPushButton::clicked, this, [this]() { restartCurrentTab(); });
    connect(stopTabButton_, &QPushButton::clicked, this, [this]() { stopCurrentTab(); });
    connect(clearTabButton_, &QPushButton::clicked, this, [this]() { clearCurrentTab(); });
    connect(followOutputCheck_, &QCheckBox::toggled, this, [this](bool checked) {
        for (int i = 0; i < tabWidget_->count(); ++i) {
            if (auto* session = asSession(tabWidget_->widget(i))) {
                session->setFollowOutput(checked);
            }
        }
    });
    connect(tabWidget_, &QTabWidget::currentChanged, this, [this](int) { updateHeader(); });
    connect(tabWidget_, &QTabWidget::tabCloseRequested, this, [this](int index) {
        if (tabWidget_->count() <= 1) {
            if (auto* session = asSession(tabWidget_->widget(0))) {
                session->clearOutput();
            }
            return;
        }
        auto* widget = tabWidget_->widget(index);
        tabWidget_->removeTab(index);
        delete widget;
        updateHeader();
    });

    addTerminalTab();
}

TerminalPage::~TerminalPage() = default;

QWidget* TerminalPage::currentSession() const {
    return tabWidget_ ? tabWidget_->currentWidget() : nullptr;
}

void TerminalPage::addTerminalTab() {
    auto* session = new ShellSessionWidget(followOutputCheck_->isChecked(), tabWidget_);
    const int index = tabWidget_->addTab(session, sessionTitleForIndex(tabWidget_->count()));
    tabWidget_->setCurrentIndex(index);
    wireSessionSignals(session, tabWidget_->tabText(index));
    updateHeader();
}

void TerminalPage::closeCurrentTab() {
    if (!tabWidget_ || tabWidget_->count() == 0) {
        return;
    }
    if (tabWidget_->count() == 1) {
        if (auto* session = asSession(tabWidget_->widget(0))) {
            session->clearOutput();
        }
        return;
    }
    auto* widget = tabWidget_->currentWidget();
    tabWidget_->removeTab(tabWidget_->currentIndex());
    delete widget;
    updateHeader();
}

void TerminalPage::restartCurrentTab() {
    if (auto* session = asSession(currentSession())) {
        session->restartShell();
        updateHeader();
    }
}

void TerminalPage::stopCurrentTab() {
    if (auto* session = asSession(currentSession())) {
        session->stopShell();
        updateHeader();
    }
}

void TerminalPage::clearCurrentTab() {
    if (auto* session = asSession(currentSession())) {
        session->clearOutput();
        updateHeader();
    }
}

void TerminalPage::updateHeader() {
    auto* session = asSession(currentSession());
    if (!session) {
        shellInfoLabel_->setText(QStringLiteral("No terminal session active."));
        statusLabel_->setText(QStringLiteral("Open a tab to start using the embedded shell."));
        return;
    }

    const auto activeTab = tabWidget_->currentIndex() >= 0
                               ? tabWidget_->tabText(tabWidget_->currentIndex())
                               : QStringLiteral("Tab");
    shellInfoLabel_->setText(QStringLiteral("%1 | %2 | %3")
                                 .arg(activeTab, session->shellInfoText(), session->workingDirText()));
    statusLabel_->setText(QStringLiteral("%1 | Output scrollback is %2.")
                              .arg(session->statusText(),
                                   followOutputCheck_->isChecked() ? QStringLiteral("following live output")
                                                                   : QStringLiteral("manual")));
}

void TerminalPage::wireSessionSignals(QWidget* session, const QString& title) {
    Q_UNUSED(title);
    if (auto* shellSession = asSession(session)) {
        shellSession->setObjectName(QStringLiteral("terminalSession"));
    }
}

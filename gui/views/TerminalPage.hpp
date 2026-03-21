#pragma once

#include <QWidget>
#include <QProcess>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

class TerminalPage : public QWidget {
    Q_OBJECT
public:
    explicit TerminalPage(QWidget* parent = nullptr);
    ~TerminalPage() override;

private:
    void startShell();
    void stopShell();
    void sendCommand();
    void appendOutput(const QString& text);
    QString shellProgram() const;
    QStringList shellArguments() const;
    QString shellDisplayName() const;
    QString commandPrompt() const;

    QProcess process_;
    QLabel* shellInfoLabel_{nullptr};
    QLabel* statusLabel_{nullptr};
    QPlainTextEdit* outputView_{nullptr};
    QLineEdit* commandEdit_{nullptr};
    QPushButton* runButton_{nullptr};
    QPushButton* restartButton_{nullptr};
    QPushButton* clearButton_{nullptr};
};

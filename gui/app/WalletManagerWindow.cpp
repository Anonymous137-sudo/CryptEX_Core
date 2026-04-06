#include "WalletManagerWindow.hpp"

#include <QVBoxLayout>
#include <QWidget>

WalletManagerWindow::WalletManagerWindow(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(QStringLiteral("Wallet Manager"));
    resize(920, 680);
    setMinimumSize(780, 560);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(6);
}

void WalletManagerWindow::setPage(QWidget* page) {
    if (!page) {
        return;
    }

    if (content_) {
        content_->setParent(nullptr);
    }
    content_ = page;
    content_->setParent(this);
    if (auto* root = qobject_cast<QVBoxLayout*>(layout())) {
        root->addWidget(content_);
    }
}

void WalletManagerWindow::showWindow() {
    show();
    raise();
    activateWindow();
}

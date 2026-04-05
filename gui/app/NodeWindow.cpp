#include "NodeWindow.hpp"

#include <QIcon>
#include <QSize>
#include <QTabBar>
#include <QTabWidget>
#include <QVBoxLayout>

NodeWindow::NodeWindow(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(QStringLiteral("Node window"));
    resize(900, 640);
    setMinimumSize(760, 520);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(6);

    tabs_ = new QTabWidget(this);
    tabs_->tabBar()->setDocumentMode(true);
    tabs_->tabBar()->setExpanding(false);
    tabs_->setIconSize(QSize(16, 16));
    root->addWidget(tabs_);

    connect(tabs_, &QTabWidget::currentChanged, this, [this](int) {
        emit sectionChanged(currentSection());
    });
}

void NodeWindow::setSection(const QString& key, const QIcon& icon, const QString& label, QWidget* page) {
    if (!tabs_ || !page) {
        return;
    }

    const auto existing = indices_.find(key);
    if (existing != indices_.end()) {
        tabs_->removeTab(existing.value());
        indices_.remove(key);
    }

    page->setParent(tabs_);
    const int index = tabs_->addTab(page, icon, label);
    indices_.insert(key, index);
}

void NodeWindow::showSection(const QString& key) {
    if (!key.isEmpty() && indices_.contains(key)) {
        tabs_->setCurrentIndex(indices_.value(key));
    }
    show();
    raise();
    activateWindow();
}

QString NodeWindow::currentSection() const {
    if (!tabs_) {
        return QString();
    }

    const int currentIndex = tabs_->currentIndex();
    for (auto it = indices_.cbegin(); it != indices_.cend(); ++it) {
        if (it.value() == currentIndex) {
            return it.key();
        }
    }
    return QString();
}

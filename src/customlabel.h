#ifndef CUSTOMLABEL_H
#define CUSTOMLABEL_H

#include <QLabel>

class CustomLabel : public QLabel
{
    Q_OBJECT

public:
    CustomLabel(QWidget *parent) :
    QLabel(parent) {}
    ~CustomLabel() {}

signals:
    void clicked();

protected:
    virtual void enterEvent(QEvent* e)
    {
        this->setEnabled(true);
        QWidget::enterEvent(e);
    }
    virtual void leaveEvent(QEvent* e)
    {
        this->setDisabled(true);
        QWidget::leaveEvent(e);
    }
    void mousePressEvent(QMouseEvent* e)
    {
        Q_UNUSED(e);
        emit clicked();
    }
};

#endif // CUSTOMLABEL_H

#ifndef CUSTOMPUSHBUTTON_H
#define CUSTOMPUSHBUTTON_H

#include <QPushButton>

class CustomPushButton : public QPushButton
{
    Q_OBJECT

public:
    CustomPushButton(const QIcon &icon, const QString &name, QWidget *parent) :
    QPushButton(icon, name, parent) {}
    ~CustomPushButton() {}

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
};

#endif // CUSTOMPUSHBUTTON_H

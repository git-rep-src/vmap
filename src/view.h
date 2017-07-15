#ifndef VIEW_H
#define VIEW_H

#include "ui.h"
#include "element.h"

#include <string>

namespace Ui {
class View;
}

class View : public QWidget
{
    Q_OBJECT

public:
    explicit View(QWidget *parent);
    ~View();

public slots:
    void element(std::string *ret, int max);

signals:
    void request_signal();
    void send_status_signal(QString status);

private:
    Ui::View *ui;

    bool has_offset;

    int offset;

    QVector<Element*> element_vector;
};

#endif // VIEW_H

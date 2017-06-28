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
    void show_data(std::string *ret);

signals:
    void build_request_signal();

private:
    Ui::View *ui;

    bool has_offset;

    QVector<Element*> response_vector;
};

#endif // VIEW_H

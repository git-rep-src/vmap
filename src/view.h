#ifndef VIEW_H
#define VIEW_H

#include "ui.h"
#include "bulletin.h"

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
    void build_bulletin(std::string *ret, const std::string &name,
                        const std::string &version, int max);

signals:
    void request_signal();
    void status_signal(const std::string &status);

private:
    Ui::View *ui;

    bool has_offset;

    int offset;

    QVector<Bulletin*> bulletins_vector;
};

#endif // VIEW_H

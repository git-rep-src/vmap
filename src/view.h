#ifndef VIEW_H
#define VIEW_H

#include "ui.h"
#include "bulletin.h"

#include <string>
#include <sstream>

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
    void build_bulletin(std::ostringstream *ret, const std::string &name,
                        const std::string &version, int max,
                        bool has_offset);

signals:
    void counter_signal(int offset, int n_total);
    void status_signal(const std::string &status);

private:
    Ui::View *ui;

    int offset;
    int n_total;

    QVector<Bulletin*> bulletins_vector;
};

#endif // VIEW_H

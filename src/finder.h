#ifndef FINDER_H
#define FINDER_H

#include "ui.h"

#include <string>

namespace Ui {
class Finder;
}

class Finder : public QWidget
{
    Q_OBJECT

public:
    explicit Finder(QWidget *parent);
    ~Finder();

public slots:
    void request(bool has_offset = false);

signals:
    void request_signal(const std::string &req, int max);

private:
    Ui::Finder *ui;

    int offset;

    std::string query;
    std::string type;
    std::string score;
    std::string date;
    std::string order;
    std::string max;
    std::string req;

private slots:
    void set_query();
    void set_type();
    void set_score();
    void set_date();
    void set_order();
    void set_max();
};

#endif // FINDER_H

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
    void build_request(bool has_offset = false);

signals:
    void send_request_signal(std::string &req);

private:
    Ui::Finder *ui;

    int offset;

    std::string name;
    std::string version;
    std::string score;
    std::string type;
    std::string date;
    std::string order;
    std::string max;
    std::string req;
};

#endif // FINDER_H

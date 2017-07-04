#ifndef VMAP_H
#define VMAP_H

#include "ui.h"
#include "finder.h"
#include "view.h"
#include "ssl_socket.h"

#include <string>

namespace Ui {
class Vmap;
}

class Vmap : public QWidget
{
    Q_OBJECT

public:
    Vmap(QWidget *parent = 0);
    ~Vmap();

private:
    Ui::Vmap *ui;

    Finder *finder;
    View *view;
    SSL_socket *socket;

    std::string ret;

private slots:
    bool api(const std::string &req, int max);
};

#endif // VMAP_H

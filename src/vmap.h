#ifndef VMAP_H
#define VMAP_H

#include "ui.h"
#include "finder.h"
#include "view.h"
#include "ssl_socket.h"

#include <string>

#include <QTimer>

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
    QTimer *status_timer;

private slots:
    bool api(const std::string &req, const std::string &name,
             const std::string &version, int max);
    void set_status(const QString &status);
};

#endif // VMAP_H

#include "vmap.h"

#include <iostream>

Vmap::Vmap(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Vmap),
    finder(NULL),
    view(NULL),
    socket(NULL)
{
    ui->setupUi(this);

    finder = new Finder(this);
    view = new View(this);

    ui->main_layout->addWidget(finder);
    ui->main_layout->addWidget(view);
    ui->main_layout->addStretch();

    QObject::connect(finder, &Finder::send_request_signal, [&] (std::string &req) {
        if (!api(req)) {
            //ERROR
        }
    });
    QObject::connect(view, &View::build_request_signal, [&] {
        finder->build_request(true);
    });
}

Vmap::~Vmap()
{
    if (finder != NULL)
        delete finder;
    if (view != NULL)
        delete view;
    if (socket != NULL)
        delete socket;
    delete ui;
}

bool Vmap::api(std::string &req)
{
    if (socket == NULL) {
        socket = new SSL_socket;
        if (!socket->start()) {
            delete socket;
            socket = NULL;
            return false;
        }
    }

    if (!socket->write_read(req, &ret))
        return false;

    view->show_data(&ret);

    ret.clear();

    return true;
}

/*
affectedSoftware.name:apache affectedSoftware.version:2.2.1
type:packetstorm

" OR affectedPackage.packageName:" +
name +
" OR cpe:" +
name +
" AND affectedSoftware.version:" +
version +
*/

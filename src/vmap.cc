#include "vmap.h"

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

    QObject::connect(finder, &Finder::send_request_signal, [&] (const std::string &req, int max) {
        if (!api(req, max)) {
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

bool Vmap::api(const std::string &req, int max)
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

    view->show_data(&ret, max);

    ret.clear();

    return true;
}

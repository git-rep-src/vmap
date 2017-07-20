#include "vmap.h"

#include <thread>//

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

    ui->layout->addWidget(finder);
    ui->layout->addSpacing(10); // TODO: PERCENT
    ui->layout->addWidget(view);
    ui->layout->addStretch();
    ui->layout->addWidget(ui->label_status);

    QObject::connect(finder, &Finder::request_signal, [&] (const std::string &req, int max) {
        if (!api(req, max))
            set_status("<span style=color:#5c181b>REQUEST ERROR</span>");
    });
    QObject::connect(view, &View::request_signal, [&] {
        finder->request(true);
    });
    QObject::connect(view, &View::send_status_signal, [&] (QString status) {
        set_status(status);
    });
    QObject::connect(ui->button_exit, &QPushButton::pressed, [&] {
        qApp->quit();
    });

    status_timer = new QTimer(this);
    status_timer->setInterval(3000);
    QObject::connect(status_timer, &QTimer::timeout, [&] {
        ui->label_status->clear();
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

    //std::thread t(&SSL_socket::write_read, socket, req, &ret);
    //t.detach();
    //t.join();

    if (!socket->write_read(req, &ret))
        return false;

    view->element(&ret, max);

    ret.clear();

    return true;
}

void Vmap::set_status(const QString &status)
{
    ui->label_status->setText(status);
    status_timer->start();
}

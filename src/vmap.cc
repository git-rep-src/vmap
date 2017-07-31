#include "vmap.h"

Vmap::Vmap(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Vmap),
    finder(NULL),
    view(NULL),
    socket(NULL)
{
    ui->setupUi(this);
    QObject::connect(ui->exit_button, &QPushButton::pressed, [&] {
        qApp->quit();
    });

    finder = new Finder(this);
    QObject::connect(finder, &Finder::request_signal, [&] (const std::string &req, const std::string &name,
                                                           const std::string &version, int max,
                                                           bool has_offset) {
        if (!api(req, name, version, max, has_offset))
            set_status("<span style=color:#5c181b>REQUEST ERROR</span>");
    });
    QObject::connect(finder, &Finder::status_signal, [&] (const std::string status) {
        set_status(status);
    });

    view = new View(this);
    QObject::connect(view, &View::counter_signal, [&] (int offset, int n_total) {
        finder->set_counter(offset, n_total);
    });
    QObject::connect(view, &View::status_signal, [&] (const std::string status) {
        set_status(status);
    });

    ui->layout->addWidget(finder);
    ui->layout->addSpacing(QApplication::desktop()->screenGeometry().height() / 30.85);
    ui->layout->addWidget(view);
    ui->layout->addStretch();
    ui->layout->addWidget(ui->status_label);

    status_timer = new QTimer(this);
    status_timer->setInterval(3000);
    QObject::connect(status_timer, &QTimer::timeout, [&] {
        ui->status_label->clear();
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

bool Vmap::api(const std::string &req, const std::string &name,
               const std::string &version, int max,
               bool has_offset)
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

    view->build_bulletin(&ret, name, version, max, has_offset);

    ret.clear();

    return true;
}

void Vmap::set_status(const std::string &status)
{
    ui->status_label->setText(QString::fromStdString(status));
    status_timer->start();
}

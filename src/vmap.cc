#include "vmap.h"

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>

#include <sstream>

Vmap::Vmap(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Vmap),
    finder(NULL),
    view(NULL)
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
    delete ui;
}

bool Vmap::api(const std::string &url, const std::string &name,
               const std::string &version, int max,
               bool has_offset)
{
    std::ostringstream ret;
	
    try {
        curlpp::Cleanup cleanup;
        curlpp::Easy request;
        curlpp::options::Url u(url);
        curlpp::options::WriteStream ws(&ret);
        request.setOpt(u);
        request.setOpt(ws);
        request.perform();
    }
    catch(curlpp::RuntimeError & e) {
        return false;
    }
    catch(curlpp::LogicError & e) {
        return false;
    }
   
    view->build_bulletin(&ret, name, version, max, has_offset);
    
    return true;
}

void Vmap::set_status(const std::string &status)
{
    ui->status_label->setText(QString::fromStdString(status));
    status_timer->start();
}

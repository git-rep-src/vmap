#include "element.h"

#include <pwd.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <regex>

#include <QDesktopServices>

Element::Element(bool is_cve, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Element)
{
    ui->setupUi(this);
    QObject::connect(ui->button_details, &QPushButton::pressed, [=] {
        if (!ui->label_description->isVisible())
            ui->button_details->setIcon(QIcon(":/icon-less"));
        else
            ui->button_details->setIcon(QIcon(":/icon-more"));
        ui->label_description->setVisible(!ui->label_description->isVisible());
        ui->label_id->setVisible(!ui->label_id->isVisible());
        ui->label_cve->setVisible(!ui->label_cve->isVisible());
        ui->label_cvss->setVisible(!ui->label_cvss->isVisible());
        if (is_cve) {
            ui->label_cpe_vendor->setVisible(!ui->label_cpe_vendor->isVisible());
            ui->label_cpe_product->setVisible(!ui->label_cpe_product->isVisible());
            ui->label_cpe_version->setVisible(!ui->label_cpe_version->isVisible());
            ui->label_href->setVisible(!ui->label_href->isVisible());
        } else {
            ui->label_source->setVisible(!ui->label_source->isVisible());
            ui->button_save->setVisible(!ui->button_save->isVisible());
            ui->text_source->setVisible(!ui->text_source->isVisible());
        }
    });
    QObject::connect(ui->label_href, &QLabel::linkActivated, [&] (QString url) {
        QDesktopServices::openUrl(QUrl(url));
    });
    QObject::connect(ui->button_save, &QPushButton::pressed, [=] {
        if (save())
            emit send_status_signal("<span style=color:#ffffff>FILE SAVED</span>");
        else
            emit send_status_signal("<span style=color:#5c181b>FILE SAVE ERROR</span>");
    });
}

Element::~Element()
{
    delete ui;
}

void Element::set_number(int number)
{
    ui->label_number->setText(QString("%1").arg(number, 5, 10, QChar('0')));
}

void Element::set_published(std::string published)
{
    std::size_t n;

    if ((n =published.std::string::find("T")) != std::string::npos)
        published.std::string::erase(n, published.std::string::size());

    ui->label_published->setText(QString::fromStdString(published));
}

void Element::set_title(std::string title, bool is_cve, bool is_exploitdb)
{
    std::size_t n;
    std::regex re;

    if (title.std::string::size() >= (size_t)ui->label_title->width())
        title.std::string::replace((ui->label_title->width() - 3),
                                   (title.std::string::size() - (ui->label_title->width() - 3)),
                                   "...");
    if (is_cve) {
        re.assign("&quot;");
        title = std::regex_replace(title, re, "\"");
    } else if (is_exploitdb) {
        bool has_quotes = false;
        re.assign("<");
        title = std::regex_replace(title, re, "&lt;");
        re.assign(">");
        title = std::regex_replace(title, re, "&gt;");
        if ((n = title.std::string::rfind("'")) != std::string::npos) {
            title.std::string::insert((n + 1), "<span style=color:#505050> ");
            title.std::string::insert(title.std::string::size(), " </span>");
            title.std::string::replace(n, 1, " ");
            title.std::string::replace(title.std::string::find("'"), 1, " ");
            has_quotes = true;
        }
        if ((n = title.std::string::rfind(" - ")) != std::string::npos) {
            if (!has_quotes) {
                title.std::string::insert((n + 1), "<span style=color:#505050> ");
                title.std::string::insert(title.std::string::size(), " </span>");
            }
            title.std::string::replace(title.std::string::rfind(" - "), 2, " ");
        }
    }

    ui->label_title->setText(QString::fromStdString(title));
}

void Element::set_score(float score)
{
    if (score >= 7)
        ui->label_score->setProperty("type", "score-high");
    else if ((score >= 4) && (score < 7))
        ui->label_score->setProperty("type", "score-medium");

    ui->label_score->setText(QString::number(score));
}

void Element::set_description_cve(std::string description, std::vector<std::string> cve, bool is_exploitdb)
{
    std::size_t i;
    std::size_t n;
    std::string buf;
    std::regex re("(<span class=\"vulners-highlight\">)|(</span>)");

    if (cve.size() != 0) {
        for (i = 0; i < cve.size(); i++) {
            cve[i] = std::regex_replace(cve[i], re, "");
            if ((n = cve[i].std::string::find("CVE-")) != std::string::npos)
                cve[i].std::string::erase(n, 4);
            if (i != (cve.size() - 1))
               cve[i].std::string::insert(cve[i].size(), "<br>");
            ui->label_cve->setText(ui->label_cve->text() + QString::fromStdString(cve[i]));
        }
    } else {
        if (is_exploitdb && ((n = description.std::string::find("CVE-")) != std::string::npos)) {
            std::istringstream ss(description.std::string::substr(n, ((description.std::string::find(".", n) - n) + 1)));
            while (std::getline(ss, buf, ',')) {
                if (((i = buf.std::string::find("-")) != std::string::npos)) {
                    if (buf.std::string::find(".") == std::string::npos)
                        ui->label_cve->setText(ui->label_cve->text() +
                                               QString::fromStdString(buf.std::string::substr((i + 1),
                                                                                              (buf.size() - (i + 1)))) +
                                                                                              "<br>");
                    else
                        ui->label_cve->setText(ui->label_cve->text() +
                                               QString::fromStdString(buf.std::string::substr((i + 1),
                                                                                              (buf.size() - (i + 2)))));
                }
            }
            description.std::string::replace((n - 2), (ss.str().size() + 1), "");
        } else {
            ui->label_cve->setText(ui->label_cve->text() + "NONE");
        }
    }

    ui->label_description->setText(QString::fromStdString(description));
}

void Element::set_id(std::string id)
{
    ui->label_id->setText(ui->label_id->text() + QString::fromStdString(id));
}

void Element::set_cvss(std::string cvss)
{
    std::size_t n;

    if ((n = cvss.std::string::find("AV:")) != std::string::npos)
        cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
    if ((n = cvss.std::string::find("/AC:")) != std::string::npos)
        cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> ");
    if ((n = cvss.std::string::find("/Au:")) != std::string::npos)
        cvss.std::string::erase(n, (cvss.std::string::find("/C") - n));
    if ((n = cvss.std::string::find("/C:")) != std::string::npos)
        cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
    if ((n = cvss.std::string::find("/I:")) != std::string::npos)
        cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
    if ((n = cvss.std::string::find("/A:")) != std::string::npos)
        cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
    if ((n = cvss.std::string::rfind("/")) != std::string::npos)
        cvss.std::string::erase(n, 1);

    ui->label_cvss->setText(ui->label_cvss->text() + QString::fromStdString(cvss));
}

void Element::set_cpe(std::vector<std::string> cpe)
{
    std::size_t i;
    std::size_t n;
    std::string buf;
    std::regex re("(<span class=\"vulners-highlight\">)|(</span>)");

    for (i = 0; i < cpe.size(); i++) {
        cpe[i] = std::regex_replace(cpe[i], re, "");
        buf.clear();
        if ((((n = cpe[i].std::string::find("cpe:/a:")) != std::string::npos) ||
             ((n = cpe[i].std::string::find("cpe:/h:")) != std::string::npos) ||
             ((n = cpe[i].std::string::find("cpe:/o:")) != std::string::npos))) {
              cpe[i].std::string::erase(0, 7);
              buf.append(cpe[i].std::string::substr(0, cpe[i].std::string::find(":")));
              if (i != (cpe.size() - 1))
                  buf.append("<br>");
              ui->label_cpe_vendor->setText(ui->label_cpe_vendor->text() + QString::fromStdString(buf));
        }
        buf.clear();
        if ((n = cpe[i].std::string::find(":")) != std::string::npos) {
            buf.append(cpe[i].std::string::substr((n + 1), (cpe[i].std::string::rfind(":") - (n + 1))));
            if (i != (cpe.size() - 1))
                buf.append("<br>");
            ui->label_cpe_product->setText(ui->label_cpe_product->text() + QString::fromStdString(buf));
        }
        buf.clear();
        if ((n = cpe[i].std::string::rfind(":")) != std::string::npos) {
            buf.append(cpe[i].std::string::substr((n + 1), cpe[i].size()));
            if (i != (cpe.size() - 1))
                buf.append("<br>");
            ui->label_cpe_version->setText(ui->label_cpe_version->text() + QString::fromStdString(buf));
        }
    }
}

void Element::set_href(std::string href)
{
    std::regex re;

    re.assign("www.");
    href = std::regex_replace(href, re, "");
    re.assign("(http://)|(https://)");
    href = std::regex_replace(href, re, "www.");
    re.assign("=");
    href = std::regex_replace(href, re, "&#61;");
    ui->label_href->setText(ui->label_href->text() +
                            "<a href=" +
                            QString::fromStdString(href) +
                            " style=color:#3d4243; style=text-decoration:none>" +
                            QString::fromStdString(href) +
                            "</a><br>");
}

void Element::set_source(std::string source, bool is_packetstorm)
{
    std::size_t n;

    if (is_packetstorm) {
        if ((n = source.std::string::find("`")) != std::string::npos)
            source.std::string::erase(n, 1);
        if ((n = source.std::string::rfind("`")) != std::string::npos)
            source.std::string::erase(n, 1);
    }

    ui->text_source->setPlainText(QString::fromStdString(source));
}


bool Element::save()
{
    std::size_t n;
    std::string id = ui->label_id->text().toStdString();
    std::string source = ui->text_source->toPlainText().toStdString();

    if ((n = id.std::string::rfind(">")) != std::string::npos)
        id.erase(0, (n + 1));
    if ((n = id.std::string::rfind("-ID")) != std::string::npos)
        id.erase(n, 3);
    if ((n = id.std::string::find(":")) != std::string::npos)
        id.std::string::replace(n, 1, "-");

    passwd *pw = getpwuid(getuid());
    std::string home_path = pw->pw_dir;

    std::ofstream file;
    file.open(home_path + "/" + id + ".vmap");
    if (file.is_open()) {
        for (n = 0; n < source.size(); n++)
            file << source[n];
        file.close();
    } else {
        return false;
    }

    return true;
}

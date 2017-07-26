#include "bulletin.h"

#include <fstream>
#include <sstream>
#include <regex>
#include <pwd.h>
#include <unistd.h>

#include <QDesktopServices>

Bulletin::Bulletin(bool has_cpe, bool has_source, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Bulletin)
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
        if (!has_source) {
            if (has_cpe) {
                ui->label_cpe_vendor->setVisible(!ui->label_cpe_vendor->isVisible());
                ui->label_cpe_product->setVisible(!ui->label_cpe_product->isVisible());
                ui->label_cpe_version->setVisible(!ui->label_cpe_version->isVisible());
            }
            ui->label_href->setVisible(!ui->label_href->isVisible());
        } else {
            ui->label_source->setVisible(!ui->label_source->isVisible());
            ui->button_source_details->setVisible(!ui->button_source_details->isVisible());
            ui->label_source_line->setVisible(!ui->label_source_line->isVisible());
            if (ui->text_source->isVisible()) {
                ui->text_source->setHidden(true);
                ui->button_source_details->setIcon(QIcon(":/icon-source-more"));
            }
        }
    });
    QObject::connect(ui->label_href, &QLabel::linkActivated, [&] (QString url) {
        QDesktopServices::openUrl(QUrl(url));
    });
    QObject::connect(ui->button_source_details, &QPushButton::pressed, [=] {
        if (!ui->text_source->isVisible())
            ui->button_source_details->setIcon(QIcon(":/icon-source-less"));
        else
            ui->button_source_details->setIcon(QIcon(":/icon-source-more"));
        ui->text_source->setVisible(!ui->text_source->isVisible());
    });
    QObject::connect(ui->button_source_save, &QPushButton::pressed, [=] {
        if (save_source())
            emit status_signal("<span style=color:#ffffff>FILE SAVED</span>");
        else
            emit status_signal("<span style=color:#5c181b>FILE SAVE ERROR</span>");
    });
}

Bulletin::~Bulletin()
{
    delete ui;
}

void Bulletin::set_number(int number)
{
    ui->label_number->setText(QString("%1").arg(number, 5, 10, QChar('0')));
}

void Bulletin::set_published(std::string published)
{
    std::size_t n;

    if ((n = published.std::string::find("T")) != std::string::npos)
        published.std::string::erase(n, published.std::string::size());

    ui->label_published->setText(QString::fromStdString(published));
}

void Bulletin::set_title(std::string title, std::string name,
                         std::string version, bool has_quotes,
                         bool has_dash)
{
    std::size_t n;
    std::regex re;

    if (title.std::string::size() >= (size_t)ui->label_title->width())
        title.std::string::replace((ui->label_title->width() - 3),
                                   (title.std::string::size() - (ui->label_title->width() - 3)),
                                   "...");

    if (has_quotes) {
        re.assign("&quot;");
        title = std::regex_replace(title, re, "\"");
    } else if (has_dash) {
        bool was_parsed = false;
        re.assign("<");
        title = std::regex_replace(title, re, "&lt;");
        re.assign(">");
        title = std::regex_replace(title, re, "&gt;");
        if ((n = title.std::string::rfind("'")) != std::string::npos) {
            title.std::string::insert((n + 1), "<span style=color:#505050> ");
            title.std::string::insert(title.std::string::size(), " </span>");
            title.std::string::replace(n, 1, " ");
            title.std::string::replace(title.std::string::find("'"), 1, " ");
            was_parsed = true;
        }
        if ((n = title.std::string::rfind(" - ")) != std::string::npos) {
            if (!was_parsed) {
                title.std::string::insert((n + 1), "<span style=color:#505050> ");
                title.std::string::insert(title.std::string::size(), " </span>");
            }
            title.std::string::replace(title.std::string::rfind(" - "), 2, " ");
        }
    }

    if (name != "") {
        re.assign(name, std::regex::icase);
        title = std::regex_replace(title, re, "<span style=color:#ffffff; style=font-weight:bold>" + name + "</span>");
    }
    if (version != "") {
        re.assign(version, std::regex::icase);
        title = std::regex_replace(title, re, "<span style=color:#ffffff>" + version + "</span>");
    }

    ui->label_title->setText(QString::fromStdString(title));
}

void Bulletin::set_score(float score)
{
    if (score >= 7)
        ui->label_score->setProperty("type", "score-high");
    else if ((score >= 4) && (score < 7))
        ui->label_score->setProperty("type", "score-medium");

    ui->label_score->setText(QString::number(score));
}

void Bulletin::set_description_cve(std::string description, std::vector<std::string> cve,
                                  bool is_exploitdb)
{
    std::size_t i;
    std::size_t n;
    std::string buf;
    std::regex re("(<span class=\"vulners-highlight\">)|(</span>)");

    if (description != "")
        ui->label_description->setText(QString::fromStdString(description));
    else
        ui->label_description->setText("NONE");

    if (cve.size() > 0) {
        for (i = 0; i < cve.size(); i++) {
            if (cve[i] != "") {
                cve[i] = std::regex_replace(cve[i], re, "");
                if ((n = cve[i].std::string::find("CVE-")) != std::string::npos)
                    cve[i].std::string::erase(n, 4);
                if (i != (cve.size() - 1))
                   cve[i].std::string::insert(cve[i].size(), "<br>");
                ui->label_cve->setText(ui->label_cve->text() + QString::fromStdString(cve[i]));
            } else {
                ui->label_cve->setText(ui->label_cve->text() + "NONE");
            }
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
}

void Bulletin::set_id(std::string id)
{
    ui->label_id->setText(ui->label_id->text() + QString::fromStdString(id));
}

void Bulletin::set_cvss(std::string cvss)
{
    std::size_t n;

    if ((n = cvss.std::string::find("AV:")) != std::string::npos)
        cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
    if ((n = cvss.std::string::find("/AC:")) != std::string::npos)
        cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> ");
    if ((n = cvss.std::string::find("/Au:")) != std::string::npos)
        cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
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

void Bulletin::set_cpe(std::vector<std::string> cpe)
{
    if (cpe.size() > 0) {
        std::size_t i;
        std::size_t n;
        std::string buf;
        std::regex re;
        for (i = 0; i < cpe.size(); i++) {
            re.assign("(<span class=\"vulners-highlight\">)|(</span>)");
            cpe[i] = std::regex_replace(cpe[i], re, "");
            buf.clear();
            if ((cpe[i].std::string::find("cpe:/a:") != std::string::npos) ||
                (cpe[i].std::string::find("cpe:/h:") != std::string::npos) ||
                (cpe[i].std::string::find("cpe:/o:") != std::string::npos)) {
                if ((n = cpe[i].std::string::find(":", 7)) != std::string::npos) {
                    buf.append(cpe[i].std::string::substr(7, (n - 7)));
                    if (i != (cpe.size() - 1))
                        buf.append("<br>");
                    ui->label_cpe_vendor->setText(ui->label_cpe_vendor->text() + QString::fromStdString(buf));
                    cpe[i].std::string::erase(0, (n + 1));
                }
            }
            buf.clear();
            if ((n = cpe[i].std::string::find(":")) != std::string::npos) {
                buf.append(cpe[i].std::string::substr(0, n));
                if (i != (cpe.size() - 1))
                    buf.append("<br>");
                ui->label_cpe_product->setText(ui->label_cpe_product->text() + QString::fromStdString(buf));
                cpe[i].std::string::erase(0, (n + 1));
            } else {
                buf.append(cpe[i].std::string::substr(0, cpe[i].size()));
                if (i != (cpe.size() - 1))
                    buf.append("<br>");
                ui->label_cpe_product->setText(ui->label_cpe_product->text() + QString::fromStdString(buf));
                cpe[i].std::string::erase(0, cpe[i].size());
            }
            buf.clear();
            if (cpe[i].size() != 0) {
                if (((n = cpe[i].std::string::find(":")) != std::string::npos) && (n == 0))
                        cpe[i].std::string::erase(0, 1);
                re.assign("(:)|(::)");
                cpe[i] = std::regex_replace(cpe[i], re, "-");
                buf.append(cpe[i].std::string::substr(0, cpe[i].size()));
                if (i != (cpe.size() - 1))
                    buf.append("<br>");
                ui->label_cpe_version->setText(ui->label_cpe_version->text() + QString::fromStdString(buf));
            } else {
                if (i != (cpe.size() - 1))
                    ui->label_cpe_version->setText(ui->label_cpe_version->text() + "-<br>");
                else
                    ui->label_cpe_version->setText(ui->label_cpe_version->text() + "-");
            }
        }
    } else {
        ui->label_cpe_vendor->setText(ui->label_cpe_vendor->text() + "NONE");
        ui->label_cpe_product->setText(ui->label_cpe_product->text() + "NONE");
        ui->label_cpe_version->setText(ui->label_cpe_version->text() + "NONE");
    }
}

void Bulletin::set_href(std::string href)
{
    if (href != "") {
        std::regex re;
        re.assign("www.");
        href = std::regex_replace(href, re, "");
        re.assign("=");
        href = std::regex_replace(href, re, "&#61;");
        ui->label_href->setText(ui->label_href->text() +
                                "<a href=" +
                                QString::fromStdString(href) +
                                " style=color:#3d4243; style=text-decoration:none>" +
                                QString::fromStdString(href) +
                                "</a><br>");
    } else {
        ui->label_href->setText(ui->label_href->text() + "NONE");
    }
}

void Bulletin::set_source(std::string source, bool is_packetstorm)
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


bool Bulletin::save_source()
{
    std::size_t n;
    std::string id = ui->label_id->text().toStdString();
    std::string source = ui->text_source->toPlainText().toStdString();

    if ((n = id.std::string::rfind(">")) != std::string::npos)
        id.erase(0, (n + 1));

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

#include "bulletin.h"

#include <QDir>
#include <QDesktopServices>

#include <fstream>
#include <sstream>
#include <regex>

Bulletin::Bulletin(bool has_cpe, bool has_source, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Bulletin)
{
    ui->setupUi(this);
    QObject::connect(ui->title_label, &CustomLabel::clicked, [=] {
        show_hide_details(has_cpe, has_source);
    });
    QObject::connect(ui->details_button, &QPushButton::pressed, [=] {
        show_hide_details(has_cpe, has_source);
    });
    QObject::connect(ui->href_label, &QLabel::linkActivated, [&] (QString url) {
        QDesktopServices::openUrl(QUrl(url));
    });
    QObject::connect(ui->source_details_button, &QPushButton::pressed, [=] {
        if (!ui->source_text->isVisible())
            ui->source_details_button->setIcon(QIcon(":/icon-source-less"));
        else
            ui->source_details_button->setIcon(QIcon(":/icon-source-more"));
        ui->source_text->setVisible(!ui->source_text->isVisible());
    });
    QObject::connect(ui->source_save_button, &QPushButton::pressed, [=] {
        std::string file_path = save_source();
        if (file_path != "")
            emit status_signal("<span style=color:#ffffff>FILE SAVED </span>" + file_path);
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
    ui->number_label->setText(QString("%1").arg(number, 5, 10, QChar('0')));
}

void Bulletin::set_published(std::string published)
{
    std::size_t n;

    if ((n = published.std::string::find("T")) != std::string::npos)
        published.std::string::erase(n, published.std::string::size());

    ui->published_label->setText(QString::fromStdString(published));
}

void Bulletin::set_title(std::string title, std::string name,
                         std::string version, bool has_quotes,
                         bool has_dash)
{
    std::size_t n;
    std::regex re;

    if (title.std::string::size() >= (size_t)ui->title_label->width())
        title.std::string::replace((ui->title_label->width() - 3),
                                   (title.std::string::size() - (ui->title_label->width() - 3)),
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
        title = std::regex_replace(title, re,
                                   "<span style=color:#ffffff; style=font-weight:bold>" + name + "</span>");
    }
    if (version != "") {
        re.assign(version, std::regex::icase);
        title = std::regex_replace(title, re, "<span style=color:#ffffff>" + version + "</span>");
    }

    ui->title_label->setText(QString::fromStdString(title));
}

void Bulletin::set_score(float score)
{
    if (score >= 7)
        ui->score_label->setProperty("style", "score-high");
    else if ((score >= 4) && (score < 7))
        ui->score_label->setProperty("style", "score-medium");

    ui->score_label->setText(QString::number(score));
}

void Bulletin::set_description_cve(std::string description, std::vector<std::string> cve,
                                  bool is_exploitdb)
{
    std::size_t i;
    std::size_t n;
    std::string buf;
    std::regex re("(<span class=\"vulners-highlight\">)|(</span>)");

    if (description != "")
        ui->description_label->setText(QString::fromStdString(description));
    else
        ui->description_label->setText("NONE");

    if (cve.size() > 0) {
        for (i = 0; i < cve.size(); i++) {
            if (cve[i] != "") {
                cve[i] = std::regex_replace(cve[i], re, "");
                if ((n = cve[i].std::string::find("CVE-")) != std::string::npos)
                    cve[i].std::string::erase(n, 4);
                if (i != (cve.size() - 1))
                   cve[i].std::string::insert(cve[i].size(), "<br>");
                ui->cve_label->setText(ui->cve_label->text() + QString::fromStdString(cve[i]));
            } else {
                ui->cve_label->setText(ui->cve_label->text() + "NONE");
            }
        }
    } else {
        if (is_exploitdb && ((n = description.std::string::find("CVE-")) != std::string::npos)) {
            std::istringstream ss(description.std::string::substr(n, ((description.std::string::find(".", n) - n) + 1)));
            while (std::getline(ss, buf, ',')) {
                if (((i = buf.std::string::find("-")) != std::string::npos)) {
                    if (buf.std::string::find(".") == std::string::npos)
                        ui->cve_label->setText(ui->cve_label->text() +
                                               QString::fromStdString(buf.std::string::substr((i + 1),
                                                                                              (buf.size() - (i + 1)))) +
                                                                                              "<br>");
                    else
                        ui->cve_label->setText(ui->cve_label->text() +
                                               QString::fromStdString(buf.std::string::substr((i + 1),
                                                                                              (buf.size() - (i + 2)))));
                }
            }
            description.std::string::replace((n - 2), (ss.str().size() + 1), "");
        } else {
            ui->cve_label->setText(ui->cve_label->text() + "NONE");
        }
    }
}

void Bulletin::set_id(std::string id)
{
    ui->id_label->setText(ui->id_label->text() + QString::fromStdString(id));
}

void Bulletin::set_cvss(std::string cvss)
{
    std::size_t n;

    if ((n = cvss.std::string::find("AV:L")) != std::string::npos) {
        if (cvss.std::string::find("AV:LOCAL") != std::string::npos)
            cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
        else
            cvss.std::string::replace(n, 4, "<span style=color:#a5a5a5>VECTOR</span> LOCAL");
    } else if ((n = cvss.std::string::find("AV:A")) != std::string::npos) {
        if (cvss.std::string::find("AV:ADJACENT NETWORK") != std::string::npos)
            cvss.std::string::replace(n, 19, "<span style=color:#a5a5a5>VECTOR</span> ADJACENT");
        else if (cvss.std::string::find("AV:ADJACENT") != std::string::npos)
            cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
        else
            cvss.std::string::replace(n, 4, "<span style=color:#a5a5a5>VECTOR</span> ADJACENT");
    } else if ((n = cvss.std::string::find("AV:N")) != std::string::npos) {
        if (cvss.std::string::find("AV:NETWORK") != std::string::npos)
            cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
        else
            cvss.std::string::replace(n, 4, "<span style=color:#a5a5a5>VECTOR</span> NETWORK");
    } else if ((n = cvss.std::string::find("AV:P")) != std::string::npos) {
        if (cvss.std::string::find("AV:PHYSICAL") != std::string::npos)
            cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
        else
            cvss.std::string::replace(n, 4, "<span style=color:#a5a5a5>VECTOR</span> PHYSICAL");
    } else if ((n = cvss.std::string::find("AV:U")) != std::string::npos) {
        if (cvss.std::string::find("AV:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 3, "<span style=color:#a5a5a5>VECTOR</span> ");
        else
            cvss.std::string::replace(n, 4, "<span style=color:#a5a5a5>VECTOR</span> UNKNOWN");
    }
    if ((n = cvss.std::string::find("/AC:L")) != std::string::npos) {
        if (cvss.std::string::find("/AC:LOW") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> LOW");
    } else if ((n = cvss.std::string::find("/AC:M")) != std::string::npos) {
        if (cvss.std::string::find("/AC:MEDIUM") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> MEDIUM");
    } else if ((n = cvss.std::string::find("/AC:H")) != std::string::npos) {
        if (cvss.std::string::find("/AC:HIGH") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> HIGH");
    } else if ((n = cvss.std::string::find("/AC:U")) != std::string::npos) {
        if (cvss.std::string::find("/AC:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>COMPLEXITY</span> UNKNOWN");
    }
    if ((n = cvss.std::string::find("/Au:N")) != std::string::npos) {
        if (cvss.std::string::find("/Au:NONE") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> NONE");
    } else if ((n = cvss.std::string::find("/Au:S")) != std::string::npos) {
        if (cvss.std::string::find("/Au:SINGLE") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> SINGLE");
    } else if ((n = cvss.std::string::find("/Au:M")) != std::string::npos) {
        if (cvss.std::string::find("/Au:MULTIPLE") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> MULTIPLE");
    } else if ((n = cvss.std::string::find("/Au:L")) != std::string::npos) {
        if (cvss.std::string::find("/Au:LOW") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> LOW");
    } else if ((n = cvss.std::string::find("/Au:H")) != std::string::npos) {
        if (cvss.std::string::find("/Au:HIGH") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> HIGH");
    } else if ((n = cvss.std::string::find("/Au:U")) != std::string::npos) {
        if (cvss.std::string::find("/Au:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> ");
        else        
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>AUTHENTICATION</span> UNKNOWN");
    }
    if ((n = cvss.std::string::find("/PR:N")) != std::string::npos) {
        if (cvss.std::string::find("/PR:NONE") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> ");
        else
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> NONE");
    } else if ((n = cvss.std::string::find("/PR:L")) != std::string::npos) {
        if (cvss.std::string::find("/PR:LOW") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> ");
        else
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> LOW");
    } else if ((n = cvss.std::string::find("/PR:H")) != std::string::npos) {
        if (cvss.std::string::find("/PR:HIGH") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> ");
        else
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> HIGH");
    } else if ((n = cvss.std::string::find("/PR:U")) != std::string::npos) {
        if (cvss.std::string::find("/PR:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> ");
        else
            cvss.std::string::replace(n, 5, "&nbsp;&nbsp;<span style=color:#a5a5a5>PRIVILEGES</span> UNKNOWN");
    }
    if ((n = cvss.std::string::find("/C:N")) != std::string::npos) {
        if (cvss.std::string::find("/C:NONE") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> NONE");
    } else if ((n = cvss.std::string::find("/C:P")) != std::string::npos) {
        if (cvss.std::string::find("/C:PARTIAL") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> PARTIAL");
    } else if ((n = cvss.std::string::find("/C:C")) != std::string::npos) {
        if (cvss.std::string::find("/C:COMPLETE") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> COMPLETE");
    } else if ((n = cvss.std::string::find("/C:L")) != std::string::npos) {
        if (cvss.std::string::find("/C:LOW") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> LOW");
    } else if ((n = cvss.std::string::find("/C:H")) != std::string::npos) {
        if (cvss.std::string::find("/C:HIGH") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> HIGH");
    } else if ((n = cvss.std::string::find("/C:U")) != std::string::npos) {
        if (cvss.std::string::find("/C:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>CONFIDENTIALITY</span> UNKNOWN");
    }
    if ((n = cvss.std::string::find("/I:N")) != std::string::npos) {
        if (cvss.std::string::find("/I:NONE") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> NONE");
    } else if ((n = cvss.std::string::find("/I:P")) != std::string::npos) {
        if (cvss.std::string::find("/I:PARTIAL") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> PARTIAL");
    } else if ((n = cvss.std::string::find("/I:C")) != std::string::npos) {
        if (cvss.std::string::find("/I:COMPLETE") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> COMPLETE");
    } else if ((n = cvss.std::string::find("/I:L")) != std::string::npos) {
        if (cvss.std::string::find("/I:LOW") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> LOW");
    } else if ((n = cvss.std::string::find("/I:H")) != std::string::npos) {
        if (cvss.std::string::find("/I:HIGH") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> HIGH");
    } else if ((n = cvss.std::string::find("/I:U")) != std::string::npos) {
        if (cvss.std::string::find("/I:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>INTEGRITY</span> UNKNOWN");
    }
    if ((n = cvss.std::string::find("/A:N")) != std::string::npos) {
        if (cvss.std::string::find("/A:NONE") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> NONE");
    } else if ((n = cvss.std::string::find("/A:P")) != std::string::npos) {
        if (cvss.std::string::find("/A:PARTIAL") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> PARTIAL");
    } else if ((n = cvss.std::string::find("/A:C")) != std::string::npos) {
        if (cvss.std::string::find("/A:COMPLETE") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> COMPLETE");
    } else if ((n = cvss.std::string::find("/A:L")) != std::string::npos) {
        if (cvss.std::string::find("/A:LOW") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> LOW");
    } else if ((n = cvss.std::string::find("/A:H")) != std::string::npos) {
        if (cvss.std::string::find("/A:HIGH") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> HIGH");
    } else if ((n = cvss.std::string::find("/A:U")) != std::string::npos) {
        if (cvss.std::string::find("/A:UNKNOWN") != std::string::npos)
            cvss.std::string::replace(n, 3, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> ");
        else
            cvss.std::string::replace(n, 4, "&nbsp;&nbsp;<span style=color:#a5a5a5>AVAILABILITY</span> UNKNOWN");
    }
    if ((n = cvss.std::string::rfind("/")) != std::string::npos)
        if (n == (cvss.std::string::length() - 1))
            cvss.std::string::erase(n, 1);

    ui->cvss_label->setText(ui->cvss_label->text() + QString::fromStdString(cvss));
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
                    ui->cpe_vendor_label->setText(ui->cpe_vendor_label->text() + QString::fromStdString(buf));
                    cpe[i].std::string::erase(0, (n + 1));
                }
            }
            buf.clear();
            if ((n = cpe[i].std::string::find(":")) != std::string::npos) {
                buf.append(cpe[i].std::string::substr(0, n));
                if (i != (cpe.size() - 1))
                    buf.append("<br>");
                ui->cpe_product_label->setText(ui->cpe_product_label->text() + QString::fromStdString(buf));
                cpe[i].std::string::erase(0, (n + 1));
            } else {
                buf.append(cpe[i].std::string::substr(0, cpe[i].size()));
                if (i != (cpe.size() - 1))
                    buf.append("<br>");
                ui->cpe_product_label->setText(ui->cpe_product_label->text() + QString::fromStdString(buf));
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
                ui->cpe_version_label->setText(ui->cpe_version_label->text() + QString::fromStdString(buf));
            } else {
                if (i != (cpe.size() - 1))
                    ui->cpe_version_label->setText(ui->cpe_version_label->text() + "-<br>");
                else
                    ui->cpe_version_label->setText(ui->cpe_version_label->text() + "-");
            }
        }
    } else {
        ui->cpe_vendor_label->setText(ui->cpe_vendor_label->text() + "NONE");
        ui->cpe_product_label->setText(ui->cpe_product_label->text() + "NONE");
        ui->cpe_version_label->setText(ui->cpe_version_label->text() + "NONE");
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
        ui->href_label->setText(ui->href_label->text() +
                                "<a href=" +
                                QString::fromStdString(href) +
                                " style=color:#3d4243; style=text-decoration:none>" +
                                QString::fromStdString(href) +
                                "</a><br>");
    } else {
        ui->href_label->setText(ui->href_label->text() + "NONE");
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

    ui->source_text->setPlainText(QString::fromStdString(source));
}

void Bulletin::show_hide_details(bool has_cpe, bool has_source)
{
    if (!ui->description_label->isVisible())
        ui->details_button->setIcon(QIcon(":/icon-less"));
    else
        ui->details_button->setIcon(QIcon(":/icon-more"));
    ui->description_label->setVisible(!ui->description_label->isVisible());
    ui->id_label->setVisible(!ui->id_label->isVisible());
    ui->cve_label->setVisible(!ui->cve_label->isVisible());
    ui->cvss_label->setVisible(!ui->cvss_label->isVisible());
    if (!has_source) {
        if (has_cpe) {
            ui->cpe_vendor_label->setVisible(!ui->cpe_vendor_label->isVisible());
            ui->cpe_product_label->setVisible(!ui->cpe_product_label->isVisible());
            ui->cpe_version_label->setVisible(!ui->cpe_version_label->isVisible());
        }
        ui->href_label->setVisible(!ui->href_label->isVisible());
    } else {
        ui->source_label->setVisible(!ui->source_label->isVisible());
        ui->source_details_button->setVisible(!ui->source_details_button->isVisible());
        ui->source_line_label->setVisible(!ui->source_line_label->isVisible());
        if (ui->source_text->isVisible()) {
            ui->source_text->setHidden(true);
            ui->source_details_button->setIcon(QIcon(":/icon-source-more"));
        }
    }
}

std::string Bulletin::save_source()
{
    std::size_t n;
    std::string id = ui->id_label->text().toStdString();
    std::string source = ui->source_text->toPlainText().toStdString();   

    if ((n = id.std::string::rfind(">")) != std::string::npos)
        id.erase(0, (n + 1));

    std::ofstream file;
    file.open(QDir::homePath().toStdString() + "/" + id + ".vmap");
    if (file.is_open()) {
        for (n = 0; n < source.size(); n++)
            file << source[n];
        file.close();
    } else {
        return "";
    }

    return QDir::homePath().toStdString() + "/" + id + ".vmap";
}
